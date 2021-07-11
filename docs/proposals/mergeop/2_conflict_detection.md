# **Conflict Detection**

## Types of Merge Conflicts

When merging snapshots, a conflict occurs when the contents of any two snapshots being merged overlap with each other in a way that results in data or metadata from only one or the other (not both) appearing in the final merged result. In other words, it’s a case where the order of the merge matters.

These conflicts can be broken down into several different types:
1. Deletions
    1. Whiteout from one layer deletes file in other layer
    2. Opaque dir from one layer blocks out dir in other layer
2. Overwrites
    1. File from one layer overwrites file in other layer
    2. Directory overwrites directory in other layer
        1. In this case, directory metadata (i.e. mtime, permissions, etc.) will be overwritten, but contents of the directories are merged
    3. Files can also overwrites directories and vice versa if they share the same path

## Use Cases

Different use cases call for different behavior when conflicts are encountered during a merge. Some may want conflicts to be allowed in order to support one layer deleting the contents present in lower layers. Other use cases may consider these conflicts to be errors on the part of the user and prefer to prevent them. 

Use cases to support in the first iteration:
1. Unrestricted - allow all deletions+overwrites by default, but enable visibility into when they occur
2. Restricted - deletions result in an error, file overwrites result in error, directory overwrites don’t result in error

Use cases that should be possible in future iterations:
1. Dockerfile Copy backend - overwrites are allowed, deletions are discarded
    1. "Discarded" is different from “doesn’t return error”. It means they don’t have any effect at all between independent snapshots
2. Resolve Conflicts - Ability to merge conflicting files using arbitrary code
    1. I.e. merge conflicting /etc configuration files or conflicting dpkg state files

## LLB

LLB’s MergeOp will be accept options that change the behavior of conflict handling in the merge. Conflict handling will thus be a property of individual merges rather than a property of layers or a global option of the Buildkit client/daemon.

Options that will be supported in the first iteration:
1. AllowDeletions bool
    1. Enables/disables whether whiteout/opaque conflicts result in error or not
2. AllowFileOverwrites bool
    1. Enables/disables whether files overwriting each other result in error or not
3. AllowDirectoryOverwrites bool
    1. Enables/disables whether directories overwriting each others’ metadata result in error or not

Future extensions to support more use cases are detailed in the appendix.

Clients that want to allow merge conflicts may still want to be aware when they happen in order to enable debugging.
* This can be implemented by including data on merge conflicts as part of the ExporterResponse map in the SolveResponse proto. This will be returned to clients using the Solve API for all export types that include a merge with conflicts, but for image exports in particular that data will additionally be present in the exported image metadata, making it accessible after pushing/pulling to/from registries. This will be detailed more in a doc on image export.
* We may also need to eventually support a more frontend-centric approach here, such as adding a GetConflicts API in the gateway client, which will allow frontends to expose the conflict information however they want.

## Conflict Detection

In order to detect conflicts, Buildkit needs to make comparisons between the snapshots being merged. This will be done by loading filesystem metadata into in-memory data structures and then using those data structures to locate the conflicts. This approach is chosen for a few reasons:
1. Because we can (de)serialize this data structure, we can cache it (in the cache package’s metadata store) and thus minimize i/o and syscalls needed to do conflict detection. This grows in significance as the number of files in layers increases.
    1. This serder will also be needed anyways when we need to export this same serialized metadata as part of images in order to support "lazy" conflict detection that doesn’t require first pulling a full image.
2. It can serve as a platform for other future optimizations (outside the scope of MergeOp) that involve optimizing operations, such as FileOps, that modify and create layers.

We will write our own implementation of this functionality rather than relying on third-party code (see comparison of this approach with others in the appendix):
* We can use a fairly straightforward representation where the filesystem metadata of each layer is represented as a tree of "inodes" but each inode also includes backlinks to any previous inodes it overwrites from a lowerdir of the overlay.
* Additionally, to support (de)serialization of this data structure, we will simply use the tar format, but instead of including actual file data the tar archive will consist of zero-sized files and thus consist only of tar headers, which have all the metadata we need for the file.
    * When storing serialized data in the cache metadata, we will also include a format specifier, enabling us to support other formats in the future if ever needed
    * It’s worth noting that there are degenerate cases where storing this metadata may noticeably increase disk+memory usage, namely where there are very large numbers of files created in a layer.
        * For example, if there is 128 bytes of file/dir metadata, 100k files+dirs would be about 12 MB of metadata. As a reference, the base ubuntu image has just under 3k files, so it’s unlikely this should become meaningful for all but the most extreme cases.

An outline of the (internal-only) interface used for this is also in the appendix.

## Cache Modifications + Opportunistic Optimizations

When new layers are imported or created in the cache as refs, their FS metadata will be read, serialized and stored in the cache’s existing metadata store, which will be used for any conflict detection needed for the ref going forward. This can also be done lazily if desired for performance.

cache.Accessor’s Merge method can be provided conflict detection opts through the "opts ...RefOption" arg, similar to the other methods of that interface. If there is a conflict and one of those opts indicate that conflict type should result in an error, then an error will be returned here to the caller.

After checking for any conflicts, the Merge method will now be able to opportunistically optimize the actual merge of snapshots based on which types of conflicts exist between layers.

In particular, the fallback case no longer always has to use the full differ/applier to ensure that deletions between merged layers are honored. Instead, when deletion conflicts are not allowed it can just use more straightforward FS copy functions (such as those already in use by buildkit) to apply merged layers. This saves it from needing to export layers to the content store.

# **Appendix**

## Future Merge Options

While they won’t be included in the initial implementation, eventually additional options such as the following should be possible to add-on:

1. DiscardDeletions bool
    1. Enables/disables whether whiteout/opaques will be completely discarded and not have any effect on the merge result
        1. This is useful for emulation of Dockerfile’s COPY
    2. For the efficient overlay implementation, this can be accomplished through use of nested overlays (as once an overlay is created, whiteouts+opaques are no longer visible, making them hidden when the overlay mount is used as a lowerdir)
2. ConflictHandlers []ConflictHandler
    1. Allows file conflicts to be resolved by arbitrary code (maybe an ExecOp that will be setup with mounts that provide the conflicting files and a mount to write the resolution under)

## Conflict Detection Interface

This interface will be internal-only, but will look something like this:

```
import "io/fs"

type FSMetadata interface {
    Stat(name string) (fs.FileInfo, error)
    ReadDir(name string) ([]fs.DirEntry, error)
    // If this FSMetadata was created by merging other FSMetadatas, then
    // Lowers will return those others making up the merge
    Lowers() []FSMetadata

    // Conflicts will return any conflicts that are present due to the merging
    // of this FSMetadata’s Lowers (if any). Importantly, it does not 
    // "recurse" in that if there is a lower that itself is a merge w/
    // conflicts, those will not also be returned here. This is important
    // because we may, for example, often import images that have multiple
    // layers with conflicts, but we don’t care about those in this "level"
    // of the merge.
    Conflicts() []Conflict
}

type ConflictType int

const (
    Whiteout ConflictType = iota
    Opaque
    FileOverwrite
    DirectoryOverwrite
)

type Conflict struct {
    Type ConflictType
    Path string
    // higher is the merged FSMetadata that overrides in this conflict
    Higher FSMetadata
    // lower is the merged FSMetadata that gets overridden in this conflict
    Lower FSMetadata
}

func Merge(lowers []FSMetadata) FSMetadata {
}

// ReadLayer is similar to the Differ in that it compares two directories, but
// in this case it returns an FSMetadata object instead of writing a tarball
// to the content store. This will be used when we need to first load the
// metadata for a snapshot.

func ReadLayer(lowerdir, upperdir string) FSMetadata {
    // Implementation will use continuity’s diff utils, but with a changeFunc
    // that creates an FSMetadata
}

func Marshal(fs FSMetadata) ([]byte, error) {
}

func Unmarshal(marshalled []byte) (FSMetadata, error) {
}
```

## Conflict Detection Alternatives

While the doc proposes we write our own code implementing conflict detection for now, there are a few existing userspace 
emulations of overlayfs that were considered for implementing our layer conflict detection features:

* GVisor
    * Pros
        * [Fully emulated vfs of overlay](https://pkg.go.dev/gvisor.dev/gvisor@v0.0.0-20210601224053-36d32739e7aa/pkg/sentry/fs#NewOverlayRoot), including write operations
        * [Seems to support serder](https://pkg.go.dev/gvisor.dev/gvisor@v0.0.0-20210601224053-36d32739e7aa/pkg/sentry/fs#Inode.StateSave)
    * Cons 
        * It’s just a library for gvisor not guaranteed to be supported externally w/out breaking changes
        * Even importing it may be a huge challenge, see for example [the README of this fork of gvisor’s netstack](https://github.com/inetaf/netstack).
* Fuse-overlayfs
    * Pros
        * Fully emulated vfs of overlay, including write operations
    * Cons
        * In C
        * Not easily usable as a library, difficult-to-impossible to disentangle from FUSE (which we don’t need)
        * No serder
* Write our own
    * Pros
        * No issues with importing or externally caused breaking changes
        * Can implement exactly the functionality we need now rather than pull in lots of code we don’t need
    * Cons
        * Have to write our own versions of code that already exists in one form or another in some external libraries

Overall, gvisor’s library was the strongest third-party option, but the current iteration of this design does not actually require support for emulating write operations on an overlay vfs (just read-only stats) so gvisor’s biggest pro is not very meaningful right now.

Given the significant maintenance cost of importing and using that third-party library, it was ruled out for now. If, in the future, we need to support write operations on an overlay vfs, gvisor can be re-evaluated against the cost of implementing that functionality in Buildkit alone. The change can be made at that time in a completely backwards-compatible way given that this choice is buried deep in the Buildkit daemon’s implementation and not a direct influence on any public interfaces.

## Serialization Alternatives

There were several choices for which format to use when (de)serializing layer filesystem metadata:

* Tar
    * Pros
        * Already in heavy use in the codebase, plenty of util functions to either re-use or use as a reference
        * Supports all the file metadata we need while also allowing us to skip storing actual file contents
    * Cons
        * The format is not perfectly optimized for our use case, so there may be more overhead than strictly necessary when converting between its format and our in-memory data structures used for conflict detection
        * The tar format is not exactly a pleasure to use as a developer (though this is partially alleviated by the existing tooling around it)
* [Continuity’s Manifest+Resource Proto](https://github.com/containerd/continuity/blob/33a84563724b68f70fc71fbb632cf9e0ad60ba5d/proto/manifest.proto#L7)
    * Pros
        * An existing format that has already underwent careful thought+design in terms of creating platform-agnostic representations of filesystems
        * Proto is already used in the codebase for serder of API objects
    * Cons
        * The format is not perfectly optimized for our use case of conflict detection (same as Tar)
        * Not clear if the continuity package is maintained much these days besides the util functions under fs used by containerd’s differ (which the proto is separate from). We may become partially or fully responsible for maintenance of the proto and thus have to deal with any other consumers of it that exist out in the world.
* [Stargz's TOC format](https://github.com/containerd/stargz-snapshotter/blob/v0.6.4/docs/stargz-estargz.md#toc-tocentries-and-footer)
    * Pros
      * An existing format being used today that has already underwent careful thought+design in terms of creating platform-agnostic representations of filesystems
    * Cons
      * Focused on a somewhat different use case and thus has more than we really need, such as support for specifying
        individual chunks of layers.
      * Ties us into any changes needed by stargz, which are likely not often going to be directly relevent to the use 
        case of this doc.
* Custom Proto or JSON
    * Pros
        * Can customize to our exact requirements, including optimizing the format to minimize overhead when converting between it and our in-memory data structures used for conflict detection
    * Cons
        * Have to write it ourselves

Overall, the Tar option felt like the least amount of overhead in terms of initial development and maintenance. The biggest possible downside is the overhead of converting between it and our in-memory representations of filesystem metadata, but it feels like a premature optimization to assume that overhead is significant in the real-world.

As mentioned in the doc, we will include a format annotation with this serialized metadata, so if we want to support a different format eventually, that will be achievable in a backwards-compatible way.
