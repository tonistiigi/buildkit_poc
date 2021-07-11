# **Merge+Diff Import/Export**

## **Requirements**
1. Exported images are usable by runtimes unaware of merge and diff op such as Docker and containerd.
2. Merged images with different combinations of the same layers differ only in their manifest and other metadata, layers are the same
3. All file metadata such as mtime is preserved during export
4. Support for all export types; both OCI and Docker images, tarballs, local files, etc.
5. Best effort compatibility with major registries (Dockerhub, Docker’s on-prem registry implementation, comparable offerings from AWS/Azure/Google/Github/etc.)

## Remotes

The GetRemote method on refs in the cache package serves as the main interface between refs and all the export code. When we export refs whose history contains merges and/or diffs, we need to do so in a way that is compatible with runtimes that are unaware of MergeOp and DiffOp. This means that GetRemote needs to "linearize" the refs into the simple “parent->child” structure that runtimes are aware of today.

To do so, GetRemote’s method signature does not need any changes but we do need to make sure that the Remote.Descriptors field is set properly when called on a ref with merges and diffs in its history:

* Merges
    * The descriptors will be ordered in the same way the corresponding layers are ordered when the ref is mounted
* Diffs
    * If the Diff was followed the "ancestor subchain" rule (described in the diff op doc), then the descriptors are ordered the same way the corresponding layers are when the ref gets mounted
    * If the Diff had to just be calculated by the differ and created as its own layer, then just that layer will be included

There is also the corner case mentioned in the DiffOp doc where single layer images that contain deletions need to include a dummy base layer underneath them to ensure that whiteout devices don’t actually show up when image is mounted. This can be handled pretty easily here too.
* Additionally, I’ve tested on 5.8 and 4.4 kernels that mounting a layer with whiteouts that has no corresponding file underneath works as we want it to; the whiteout just disappears.

An additional problem is the fact that the "history" of merges and diffs that create a ref will get lost when it is linearized during the export. This means, for example, that if you export a ref with merges in its history and then later re-import it or import it on another buildkit instance, it will be unpacked into the snapshotter as a single chain even when the efficient overlay-based merge+diff is available.

To improve this behavior, we can extend the `solver.Remote` struct with a new optional field:

```
type Remote struct {
	existing fields...
 	RefHistory []RefMetadata // Holds the metadata needed to properly
                                 // convert each descriptor to a ref in terms
                                 // of merges and diffs. Is JSON serializable.
}
```

RefHistory will get set in each Remote returned by GetRemote and can then optionally be included as an extra field in export metadata. In particular, it can be included as a field of image config json, similar to inline cache metadata today.
* See the appendix for the proposed structure of RefMetadata

Then, when pulling an image, the code will be updated to check for this RefHistory field in the image config json. If it exists, the refs for the image will be constructed not just by GetByBlob, but also through the Merge and Diff methods in cacheManager as specified by the metadata.
* There is a corner case with Diff where if the diff had to be calculated slowly, then the lower and upper inputs to it won’t be actual layers included in the image. The only way to recover them is if they are included with a remote cache import (see next section).
* Therefore, the code should handle this situation by trying to construct the diff ref from the lower and upper digests as specified in the RefHistory, but if that fails due to those digests not being known to the cache manager, then the ref will just be constructed using GetByBlob.
* The diff history is thus lost in this case unless the remote cache is used in max mode, but that feels like an acceptable tradeoff.

The FromRemote method on the Worker will also need the same update to parse RefHistory if provided. FromRemote is only ever called by the remote cache, which is discussed next.

## Remote Cache Extensions

We need to make sure that the structure of merge and diff records works with the remote cache implementation. To do this, CacheRecords will now be created for merge and diff ops:
* CacheRecords representing a Merge will have 1 Input for each of the records they are merging together
* CacheRecords representing a Diff will have 1 Input for its lower record and 1 Input for its upper record.
    * Additionally, if the Diff had to be calculated manually and created as its own layer, that layer will be set in the CacheRecord.Results.

Additionally, during remote cache import, we want to provide the RefHistory field when calling FromRemote. In order to reconstruct RefHistory, we can extend one of the [existing structures](https://github.com/moby/buildkit/blob/master/cache/remotecache/v1/spec.go):
```
type CacheRecord struct {
	...existing fields
	Type string // enum of "", “Layer”, “Merge” or “Diff”
}
```

This new `Type` field just indicates whether the cache record represents a Merge, Diff or is just a normal layer like today (in which case it's either “Layer” or, for backward compatibility, an empty string). The code can figure out the right type to set during export by looking at the RefHistory fields of remote objects.

The remote cache can also help out with another problem. Namely, the FSMetadata for each layer (used currently for conflict detection, potentially much more in the longer term) can, by default, only be reconstructed by pulling the full layer, which is unnecessarily expensive in cases where we just need to validate a merge but not actually push any new data.
* As discussed in the conflict detection doc, FSMetadata will serialized as "header-only" tars, where file metadata is set but none of the actual file contents are included.

The proposed solution is to extend the existing support for remote cache to also include FSMetadata. This is compared with alternative solutions in the appendix.

To do so, we just need to extend another one of the existing structures:
```
type CacheLayer struct {
	...existing fields
	MetadataBlob digest.Digest // digest of the FSMetadata tarball
}
```

The new `MetadataBlob` field of CacheLayer is optional and, when set, points to the FSMetadata tarball, which will now be pushed as its own “layer” (separate from the tarballs with real contents) when exporting cache. This also means these metadata tars need to be included in the cache’s manifest list. The metadata layers will just use the same layer types as the regular ones in order to maximize compatibility with registry implementations.
* In the long run, we can consider including an extra field specifying where the metadata blob is stored in case we want to, for example, store some of them in the image config json or image manifest when they are especially small and it’s more efficient to do so.

During import, the remote cache can then pass these FSMetadata blobs along to the underlying cache through RefOptions.

For inline cache mode, we will retain the existing behavior of including just metadata in the image config json. This means that we will not push any of the FSMetadata tarballs (due to the fact that such tarballs would appear as orphaned blobs to registries), so that information will be lost in this case. This hurts performance since conflicts can’t be detected lazily, but all behavior remains functionally the same otherwise.

Min and max cache modes for the non-inline case will be made to behave basically the same as today. This means that, for example, when a Diff has to be calculated manually and has its own dedicated layer, you will include not only the calculated layer but also the layers it was calculated from when running in max mode. In min mode, on the other hand, you will only include the result of the diff, as that’s all that’s needed to actually mount the final image.

In terms of backwards compatibility:
* The new fields in CacheRecord and CacheLayer are backwards compatible additions, so the config parser of older buildkit instances should just ignore them and not get any errors
* The CacheRecords representing merges and diffs won’t be usable by older versions of buildkit of course, but they should just result in cache misses rather than errors.
    * This is because the digest of merge and diff records comes from the cachekey digest, which in turn uses the actual LLB bytes as part of its input. The LLB bytes of merge, diff and any pre-existing ops can’t be the exact same.

# **Appendix**

## RefMetadata Structure
```
type RefMetadata struct {
	Type string   // enum of "Layer", “Merge”, “Diff”
	Parents []int // indexes of the ref’s parents
	Opts []string // slice of enum for the options available for merge+diff
	Blob digest.Digest // if there is a blob backing the ref, its digest
}
```

The `Type` field indicates whether the ref was a Merge, a Diff, or just a regular layer.

Values in the Parents slice will be set to indexes of the Remote.RefHistory slice.
* For Layers, there will be 0 or 1 values here depending on if the layer was base or not
* For Merges, there will be 1 index per merge input
* For Diff, there will be 2 indexes, 1 for lower and 1 for upper

Opts ensures the settings used to merge/diff are retained, which could be relevant in cases such as optimizing merges depending on the conflict detection opts.

Blob links this ref back to the actual layer in the Remote.Descriptors slice, if there is an actual layer.

## RefHistory Alternative Implementations

There is another possible way of solving the problem RefHistory solves, at least for merges. Namely, we could change the implementation of Buildkit to treat all ref chains as "merge chains". So, even when you just do an ExecOp, that is actually stored in the same way ExecOps on top of merges are stored, as its own independent snapshot. The end result would be that when efficient merges are available, buildkit only uses single layer snapshots and just merges them together to create chains.

I believe you could achieve behavior identical to that of today with this approach while also solving the problem of duplicating snapshot data when the same layer is used in different chains. You’d thus no longer need RefHistory to solve that problem.

However, this may be a very fundamental change to the codebase and feels too large+risky for this iteration. It should remain possible for a future iteration if desired though.

## FSMetadata Alternative Implementations

There are many possible solutions for where to store FSMetadata when remotely exported, a few significant ones compared:
1. (The chosen solution) Include them with remote cache exports
    1. Pros
        1. Piggybacks on existing cache import/export, which helps reduce new code and makes conceptual sense given the purpose of this is ultimately to improve performance
        2. Benefits from improvements in support for buildkit cache across registries
    2. Cons
        1. There are still some registries that don’t accept buildkit cache exports (though this is improving with time)
2. Serialize them and put them directly in the image config json
    1. Pros
        1. Simple implementation
        2. Broadly compatible with registries
    2. Cons
        1. In extreme cases, could bloat the size of the config json a meaningful amount
            1. Tar headers are padded to 512 bytes. As a reference, the base ubuntu image has a bit under 3000 files+dirs, so that’s about 1.5 MB uncompressed for that layer. Compression may help a lot, but unknown what ratio can be achieved.
            2. Also, the metadata blobs will be duplicated for every single permutation of merge. If two different merges have the same layer, their metadata blobs won’t be deduped because each export merge has its own image config json.
3. Include references to them in the image config json, push them as "layers" separately
    1. Pros
        1. Simple implementation
        2. Registries are broadly compatible in that they won’t throw errors
    2. Cons
        1. Registries won’t see that the metadata tarballs are actually referenced by anything (they don’t know about the custom image config json field), so they may consider them open for garbage collection (i.e. [docker registry’s functionality here](https://docs.docker.com/registry/garbage-collection/)).

Ultimately, option 1 was chosen because the implementation was cleanest by just extending existing functionality (rather than introducing something totally new) and the only downside is one that is improving with time.
