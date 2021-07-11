# **MergeOp**

## **Use Case**
MergeOp enables users to combine independent snapshots without necessarily having to copy data on disk or introduce
unneeded cache dependencies.

For example, right now if you have separate LLB states (for example, separate stages in a multi-stage Dockerfile build) 
whose artifacts need to be combined together into a single state, your only option is to copy them together, which 
results in wasted disk space and increased execution time. It also means that the order you combine them in is important
and if any of the "lower layer" states being combined changes, the copying of all the states being combined above it 
will be invalidated and thus need to be repeated, worsening the disk space + execution time waste even further.

With MergeOp, you will instead be able to combine states together without any actual copy of data on disk (provided the 
underlying snapshotter satisfies some requirements, as described later). All of the merged states remain independent,
so if one of them changes, that doesn't invalidate the cache chain of other states in the merge and require extra work
to recombine them together.
  * This becomes especially powerful in combination with DiffOp (described in a subsequent doc), which allows you to
    select which layers of an LLB state you want to merge and thus making it trivial to only merge together exactly what
    you want. For example, you can easily only merge together runtime artifacts, leaving buildtime dependencies out of a 
    final merged state.

For now, this design only proposes changes to Buildkit's backend and LLB. Adding support for MergeOp to higher-level
users of MergeOp is out of scope but the potential use cases (such as using this to optimize Dockerfile COPY operations)
are mentioned and considered throughout the docs.

## **Requirements**

1. Support for an LLB Op that merges the results of other LLB ops. The result of merging input ops should look the same as if you had taken the layers of the snapshots backing each input op result and applied them all on top of one another in the order provided. This has similarities with the existing llb.Copy operation but there are several key differences:
   1. It must opportunistically optimize out the copying of data on disk when the underlying host+snapshotter has support for doing so (such as via overlayfs). If such optimizations aren’t available, the implementation must have a fallback mode with behavior that is functionally identical even if much less efficient.
   2. All file metadata, including times, must be retained rather than updated at the time the merge takes place to ensure complete reproducibility.
   3. There must be optional support for retaining the deletions of files and dirs included with layer definitions and thus allowing them to have an effect when merging. So rather than just copying files and directories on top of each other, it’s more like you are merging filesystem change sets on top of each other.
2. The output of MergeOp must be usable as an LLB result in the same way that outputs of SourceOp, FileOp and ExecOp are today. This allows MergeOp to work seamlessly with the rest of LLB.
   1. For example, you must be able to use a MergeOp result as a mount in an ExecOp or as the base for a FileOp without needing to add special handling to those other Op types.

## LLB

In terms of the LLB go client, this design proposes a single new function in the client/llb package:
* `Merge(states []State, opts ...MergeOpt) State`

When merging states, the order matters, with "higher layer" states overriding and taking precedence over lower ones.
* The order of arguments is lower->higher, which is mostly arbitrary in the same way big vs. little endian is, but was chosen because it’s most intuitive and allows you to add layers to the stack by appending to the slice.

For now, Merge will only merge together the root (i.e. "/") of the provided states; there won’t be support for using selectors to merge subdirs of states.
* While this would be technically possible to implement efficiently in Buildkit alone, problems arise when trying to export such states as images for use by runtimes that are unaware of MergeOp (i.e. containerd, docker, etc.) without resorting to copying data for every different state+selector combination.

The opts will be used to configure the behavior when there are conflicts during the merge, which is detailed more in the next conflict detection doc.

Some notes on forwards compatibility:
* If we ever want to add the ability to use selectors on the input states of Merge, we can use the existing .Dir() method on States to implement choosing a subdir to merge. This means that for now we should return an error if users try to call Merge with a Dir value set to something besides "/"

### Basic Example

```
stateA := Scratch().
   	 File(Mkfile("/foo", 0777, []byte("A"))).
   	 File(Mkfile("/a", 0777, []byte("A")))

stateB := Scratch().
   	 File(Mkfile("/foo", 0777, []byte("B"))).
   	 File(Mkfile("/b", 0777, []byte("B")))

mergedState := Merge(stateA, stateB) /*
   	 /a   - contains A
   	 /b   - contains B
   	 /foo - contains B
*/

mergedState = Merge(stateB, stateA) /*
   	 /a   - contains A
   	 /b   - contains B
   	 /foo - contains A
*/
```

As you can see, the contents of /foo depend on the order of the merge, with the higher state taking precedence.

/a and /b on the other hand are exclusive to stateA and stateB and thus get merged independently.

### Deletion Example

```
stateA := Scratch().
   	 File(Mkfile("/foo", 0777, []byte("A"))).
   	 File(Mkfile("/a", 0777, []byte("A")))

stateB := stateA.
   	 File(Rm("/foo")).
   	 File(Mkfile("/b", 0777, []byte("B")))

stateC := Scratch().
   	 File(Mkfile("/foo", 0777, []byte("C"))).
   	 File(Mkfile("/c", 0777, []byte("C")))

mergedState := Merge(stateB, stateC) /*
   	 /a   - contains A
   	 /b   - contains B
   	 /c   - contains C
	 /foo - contains C
*/

mergedState = Merge(stateC, stateB) /*
   	 /a   - contains A
   	 /b   - contains B
   	 /c   - contains C
	 /foo - [doesn't exist!]
*/
```

Here you can see that deletion of a file is considered part of a layer merge in the same way the creation or overwrite of a file is. The same idea will apply to deletions of directories.

This example also illustrates that because stateB was created on top of stateA, stateA’s layers will be included when doing the merge. To be more concrete:
* `Merge(stateB, stateC)` results in layers being ordered stateC->stateB->stateA
* `Merge(stateC, stateB)` results in layers being ordered stateB->stateA->stateC

It's also worth noting that if you try to delete a file which doesn't exist and that doesn't result in an error, that
will not result in a deletion actually being included as part of the layer. Only deletion of existing files can be
included with the layer definition.

### Run Example

```
base := Image("ubuntu")
repos := Merge(
  Git("github.com/foo/foo.git", “main”),
  Git("github.com/foo/bar.git", “main”),
)

serviceA := base.
  Run(Shlex("make -C /src serviceA")).
  AddMount("/src", repos).
  Root()

serviceB := base.
  Run(Shlex("make -C /src serviceB")).
  AddMount("/src", repos).
  Root()

mergedState := Merge(serviceB, serviceA)
```

This example is partially just meant to illustrate how merged states can be used seamlessly as input mounts to ExecOps, as seen by mounting the repos state.

However, it also illustrates what may be surprising behavior. Namely, when you break down the layers of mergedState, it will look like this:
* `make -C /src serviceA` -> `ubuntu` -> `make -C /src serviceB` -> `ubuntu`

What’s perhaps unexpected is that base’s layers (the ubuntu image) end up twice in the merged layer chain and also potentially override `make -C /src serviceB` even though that ExecOp was created on top of base. The behavior many users are more likely to want in this scenario is:
* `make -C /src serviceA` -> `make -C /src serviceB` -> `ubuntu`

Essentially, in this particular case the more desirable behavior is probably something akin to a topological sort of unique States based on their dependencies.

However, forcing States to always be topologically sorted is somewhat "magical", harder to reason about at more complicated scales and limiting in that there could be cases where users actually don’t want the behavior for whatever reason.

Instead, this design proposes that llb.Merge just implements the more simple ordering of layers exactly as specified by the user and leaves higher-level libraries/tools to implement topological sorting of States by dependencies if they want. While not fully possible yet, this will be enabled by DiffOp and discussed more in that doc.

### Proto

The proposed additions to the LLB proto are:

```
message MergeConflictOpt {
    bool AllowDeletions = 0;
    bool AllowFileOverwrites = 1;
    bool AllowDirectoryOverwrites = 2;
}

message MergeInput {
	int64 input = 1;
}

message MergeOp {
	repeated MergeInput inputs = 1;
	MergeConflictOpt mergeConflictOpt = 2;
}
```

The structure of MergeOp on the proto level is similar to that of ExecOp, just much simpler since there are less options. MergeInput is comparable to ExecOp’s Mount type; it’s just a reference to an Op.Input, which indexes an input state that should be merged. The MergeOp message type itself is currently just a list of those inputs as no other options are needed for now.

The MergeConflictOpt field will be discussed later in the Conflict Detection doc.

Given their similar structure, MergeOp should be forward compatible in the same way ExecOp is forward compatible today.

## Solver

The solver package will need updates to support the new MergeOp type, namely in solver/llbsolver/ops/. The two methods it will need to implement are:
1. CacheMap - this will be like a simpler version of ExecOp’s CacheMap method where the cache key is based on the digest of the MergeOp proto and the content checksums of each input to the Merge
2. Exec - this will just need to use cache.Manager to merge the input refs together (using a new API described in the next sections) and return that ImmutableRef as a Result.

## Cache Modifications

The cache package needs to be modified to support merging ImmutableRefs and to support creating MutableRefs on top of those merged ImmutableRefs. The overall goal here is to make this change as transparent to the rest of the codebase as possible so all existing code that currently uses refs today doesn’t have to be aware of the existence of merged refs in order to use them.

This design thus proposes that we retain the existing ImmutableRef and MutableRef interfaces in the cache package, but update their underlying implementation to handle ref merges.
* The ImmutableRef.Parent method will need to be replaced with a method that just returns a list of refs for each layer in the chain, but there are only two callers of that method so it’s a very minor update.

The only significant interface change will be extending cache.Accessor with this method:
* `Merge(ctx context.Context, parents []ImmutableRef, opts ...RefOption) (ImmutableRef, error)`

Merge, as you’d expect, creates an ImmutableRef that represents the merge of the given parents and returns it to the caller. That ImmutableRef can then be used just like any other ImmutableRef can be today.
* To create a MutableRef on top of a merged ref (i.e. an ExecOp on top of a MergeOp), callers just need to use the existing CacheManager.New method and set the "parent" arg to a ref returned by a previous call to cache manager’s Merge method.
    * In practice, callers of New won’t have any idea whether the ref they are supplying as parent is a regular or merged ref as it’s all hidden behind the ImmutableRef interface.

To support this new interface, the internal implementation of the cache package will obviously need some significant updates:
1. cacheRecords will now optionally have multiple parents, which will indicate that they were created by the cacheAccessor.Merge method and represent the merging of those parents
2. When creating a Mountable for a Ref, the code will need to traverse the parents of the underlying cacheRecord to find all the individual snapshots constituting it.
    1. If the Ref has no merges in its history, this code will find at most 1 snapshot and work the exact same as it does today
    2. If however the Ref has one or more merges in its history, then the implementation will need to deal with constructing a Mountable that represents the merge of those snapshots
3. In the case where snapshots need to be merged, the code will first try to use an efficient method implemented as an extension of the Snapshotter interface (described more below). However, as discussed previously, there will also be a fallback code-branch that runs when the efficient merge isn’t available.
4. The GetRemote method of ImmutableRef will also need to be updated to account for the fact that it shouldn’t include merge refs in its list of layers, but this will be expanded on in the import/export doc.

### Efficient Snapshotter Merge

To support the efficient snapshot merge, Buildkit's snapshotter interface will be extended with the following method:
* `Merge(ctx context.Context, parents ...Mountable) (merged Mountable, cleanup func() error, err error)`

The parents provided to this snapshotter Merge method are expected to be the mountables of active snapshots created from previous calls to the Prepare and/or View methods of the underlying snapshotter interface. The returned Mountable can be used to mount the merged snapshots. The returned "func() error" is a cleanup function that should be called by the user after unmounting.

It’s expected that there is at most 1 read-write mount referenced in the list of parent mounts; more than one will result in an error.
* If there is a read-write mount in parents, all changes written to the merged mount will go to that read-write snapshot.
* If there is no read-write mount, then the merged mount will be read-only

More implementation details are provided in the appendix.

### Fallback Merge

When the efficient overlay-based merge isn’t available, the cache package code will, for now, instead fallback this process which is agnostic to the underlying snapshotter type and doesn’t require overlay support:

1. Export all the parent snapshot layers as blobs to the content store if they aren’t there already (required in order to use the Applier)
2. Create a new merged snapshot by Applying each layer of the parents on top of one another, similar to the way that an image is unpacked but now with multiple snapshot chains joined together.

There are further optimizations possible depending on the merge conflict options, which is detailed in the conflict-detection doc.

In this code-branch, merged refs will actually have their own snapshot backing them in addition to the snapshots of each of their parents (as compared with the efficient merge branch where the merged refs are completely stateless in this regard). The code will thus ensure these refs are counted when calculating disk usage and can be pruned like any other ref today.

This will also all work within the existing support for lazy operations in the cache package; expensive operations will only occur once absolutely required, such as right before a mount is going to happen.

# **Appendix**

### Support for Subdir Merge

As mentioned before, it would be ideal to support merges not only of the root of states (i.e. "/") but also arbitrary subdirs of states.

As an example:
```
stateA := Image("A")
stateB := Image("B")
mergedSubdirs := Merge(stateA.Dir("/foo"), stateB.Dir("/bar"))
```

Here, mergedSubdirs represents the merging of stateA’s `/foo`, stateB’s `/bar`. mergedSubdirs would have all those contents present at its `/`.

The primary issue for supporting this is that there’s no known way to implement export of such merges without creating different blobs for every combination of layer+subdir, which results in significant duplication even in the efficient overlay case. In the above example, exports of stateA and mergedSubdirs would result in a layer blob for the entire stateA and a separate layer blob for the contents of stateA’s `/foo`, with the data under stateA’s `/foo` duplicated between the two.

The options for enabling this feature at this time are:
1. Accept that exporting such states as images may result in significant blob duplication both locally and when pushing to remote registries
    1. This is especially unfortunate in that it becomes difficult for users to reason about whether their solves could use lots of disk space or not
2. Work with runtimes (such as containerd and docker) and possibly the OCI spec maintainers to add support for specifying that images may be mounted using subdirs of OCI image layer blobs.
    1. This is a very large project, only possible in the much longer term
    2. There are other runtime+registry modifications possible too, such as implementing support for deduplicating content store and snapshot storage on the file or even block level, but they are just as large if not larger projects.

Excluding the image export case, support for this feature in Buildkit would be relatively straightforward.
* In the efficient overlay merge case, subdir support can be implemented by setting the lower or upper dir of the overlay mount to a subdir of the snapshot mount
* For the fallback case, you can just modify the mounts provided to the differ to specify the use of a subdirs when exporting the blob to the content store

One other significant implication of this change may be that the cache package would need awareness of the fact that refs can point to subdirs of other refs rather than always being their own snapshot, but that should only require a small modification of cache.Accessor’s Merge method and internally extending the cacheRecord struct and metadata store with some new fields.

### Efficient Snapshot Merge Details

The high-level use+implementation of the Snapshotter Merge method goes as follows:
1. The caller gets mounts for each of the snapshots they want to merge together by calling View or, in the case where they want a read-write layer, Prepare.
2. Those parent mounts are provided to Merge, which combines them into a single overlayfs mount by:
    1. Setting the lowerdirs to the joined-together lowerdirs and read-only bind-mounts of the parent mounts.
    2. Optionally setting the upperdir to either the upperdir present among the parent mounts or the read-write bind-mount, depending on which is present. 
    3. The workdir can be re-used from the parents mounts if one was present.
        1. If there was only a read-write bind mount in the input (as opposed to an overlay with an upper/work dir), then we can get one by creating a temporary directory on the same filesystem as the read-write bind mount (which will be removed by the returned "cleanup" callback).
        2. Buildkit will need to handle cleaning up these temporary workdirs on startup to prevent them from leaking after an ungraceful shutdown.
3. The caller can then mount the merged overlay and use it as they would any other mount.
4. Once done, the higher level callers are expected to unmount, call the returned "cleanup" func, and then take care of each of the parent snapshots they provided to the original Merge call.
    1. The cleanup func will handle two things in this case:
        1. Removing any temporary workdirs that had to be created
        2. Looking at the resultant upperdir and identifying any opaque dirs that were created when there was no corresponding lowerdir, in which case the opaque xattr should be removed
            1. [This overlayfs behavior is purely an optimization](https://github.com/torvalds/linux/commit/97c684cc911060ba7f97c0925eaf842f159a39e8) that we don’t want.
    2. "Taking care" of the parent snapshots would include calling Commit on any read-write snapshot they provided and want to keep the changes from (or just removing the snapshot key if they want to throw those changes away)
