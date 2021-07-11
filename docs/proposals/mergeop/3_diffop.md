# **DiffOp**

## **Requirements**

1. Support for an LLB Op that takes two results as inputs, a lower and an upper, and outputs a result that, when mounted, shows a filesystem whose contents represent the changes necessary to transform the lower into the upper.
    1. In semi-formal terms, Diff is the function such that `Merge(A, Diff(A,B)) = B`
    2. The result of Diff must be usable as an LLB state like any other. It can be mounted and merged. If it contains deletions, those must have an effect during merges (depending of course on the options set for the merge).
2. DiffOp’s implementation must be opportunistically efficient and avoid creating new data or copying when possible. When not possible, it must fallback to using the slower differ that actually creates new data while still exhibiting the same functional behavior as the efficient case.

## **Use Cases**
* **(Primary Use Case)** Ability to easily Merge the results of ExecOps without including their “base” and/or their build dependencies
    * See the “Run Example” of the first MergeOp design doc for a detailed example of where this is helpful
    * While this use case is often possible without strictly requiring DiffOp (such as providing an autotools “configure” script an install prefix that points to an empty mount), the way that this is configured, if it’s configurable at all, is highly dependent on the build system the user is running. This leaves users with the problem of understanding and setting up such configuration for every permutation of build system and setup.
        * It’s also not directly possible at all in some scenarios such as when there is a wrapper script around a build that doesn’t accept any prefix settings
        * DiffOp instead gives a universal way of extracting isolated diffs that doesn’t require build configuration changes or other customizations on the part of the user.
* (Secondary benefit) Ability to find the changes between arbitrary states and represent those changes as a filesystem
    * For one example, this can be helpful for finding and summarizing changes from one version of an image to another

## LLB Go Client

A single new function will be added to the LLB Go client:
* `Diff(lower, upper State) State`

While lower and upper can be arbitrary states, the most important use case for Diff is extracting the changes made by ExecOps, allowing them to be merged independently without their original "dependency" layers. For example:
```
base := Image("base")
serviceA := Diff(base, base.Run(Shlex("make A")).Root())
serviceB := Diff(base, base.Run(Shlex("make B")).Root())
services := Merge(serviceB, serviceA) // "service A"->”service B”
```

serviceA and serviceB consist of just the changes made by running `make A` and `make B`, so when they are merged together the base image won’t be included.

More examples are in the appendix.

Similar to Merge, the first iteration will not support diffing subdirs of provided states, so we will need to return an error if a provided state has been called with Dir to set a subdir. This subdir support can then be added in the future in a backwards compatible way.

No options are needed at this time, but can be added in the future if needed as a variadic argument.

## LLB Proto

The proto changes are very straightforward and similar to MergeOp’s:

```
message DiffInput {
	int64 input = 1;
}

message DiffOp {
	DiffInput lower = 1;
	DiffInput upper = 2;
}
```

## Cache Package

The cache.Accessor interface will need one additional method:
* `Diff(ctx context.Context, lower, upper ImmutableRef, opts ...RefOption) (ImmutableRef, error)`

Diff returns an ImmutableRef representing the diff of the provided lower and upper. This ImmutableRef can then be used as any other: mounted, merged, exec’d on, etc.

Similar to merged refs, Diff will create a cacheRecord to represent the diff (or re-use a cacheRecord if an exact equivalent already exists). This requires adding two new fields to cacheRecord, lowerDiffParent and upperDiffParent, which will be set only if the ref represents the diff of those two parent refs. In this case, the existing parents field will just be nil.
* This approach is advantageous in that it retains the whole "history" of diffs, merges and normal snapshot chains that created a ref. Retaining knowledge of this history allows the cache package to opportunistically optimize certain operations as will be discussed shortly.

Also similar to merged refs, cacheRecords created by Diff may or may not have an actual snapshot underneath them depending on whether the diff can be created efficiently or not. Efficient diffs will be defined statelessly as a product of their inputs, inefficient ones will need a new snapshot created to represent them.

The primary conditions for when the mounts for a Diff ref can be created efficiently are the same as that for Merge (overlay snapshotter is enabled), but with an additional restriction: The diff must be between a lower that is a "ancestor subchain" of the upper. Say we represent chains of layers as `A->B->C->D` (where `->` means “layer dependency”), with A as the base layer and D as the top layer:

* `Diff(A->B, A->B->C->D)` **can** be implemented efficiently because `A->B` is a subchain that starts at the ancestors of `A->B->C->D`
    * The result in this case is `C->D`
* `Diff(A->B, X->Y)` can **not** be implemented efficiently, even with overlay, because `A->B` is not an ancestor subchain of `X->Y`
    * The result in this case will just be calculated by the Differ
* There are more cases discussed in the appendix

Many more optimizations are possible in theory, especially if combined with the FSMetadata interface discussed as part of the conflict-detection doc, but all beyond the most basic will remain out of scope for the first iteration and can be implemented in the future.

In general, the code will attempt to identify optimizations but if none are found it will fallback to just using the Differ+Applier to create a new snapshot that represents the diff of the two parent refs and storing that as the snapshot underlying the cacheRecord.

There are also some important implications for pruning and GC here. Namely, cacheRecords created by Diff will be holding references to their diffed parents, preventing the parents from being gc’d. For the first iteration, we will just allow this to be the behavior. In the long term, more optimizations are possible such as:
* Making diff parent refs lazy (i.e. remove local data but hold onto ref) when their snapshot/content data is no longer needed because the diff had to create its own snapshot.

## Snapshots

For the efficient overlay-based case, we’ll need to add a method to our snapshotter interface:
* `Diff(lower, upper []mount.Mount) ([]mount.Mount, error)`

This method will expect that the provided mounts follow the "ancestor subchain" rule as described above, in which case it will manipulate the mounts to create a mount representing the diff. If it can’t do so, an error will be returned.

This interface asks for mounts rather than snapshot keys because we need to deal with the fact that lower and upper may or may not be actual snapshots. For example, if lower is a merged mount, then there may not be a dedicated single snapshot underlying it, instead there’s only a mount for it (as returned by the Merge method).

One important implication of DiffOp is that it’s now possible for the base layers of snapshots to have whiteouts/opaques (previously all base layers were expected to be created from scratch, and thus not have any deletions). This causes a few significant corner cases in both the efficient and fallback modes:

1. When importing images with base layers that contain deletions, we need to make sure that the unpacked snapshots retain those deletions to ensure they exist if that snapshot is used as part of a merge in the future. By default, they won’t because the Applier will be unpacking onto scratch and thus skip them because they don’t delete anything at the time of the apply.
2. When mounting a single layer snapshot with deletions, even overlay snapshotters are forced to use bind-mounts because overlay doesn’t let you create mounts with single layers. This means that any whiteout devices will actually show up in the mount.

There are workarounds for both of the above issues that work in both the efficient and fallback modes:
1. When unpacking base layers with deletions into the snapshotter, first create a new, initially empty snapshot. This snapshot will be filled with empty files+directories for each whiteout+opaque in the layer in the content store. Then, unpack the actual base layer on top of this temp snapshot. This ensures that the deletions are stored and honored by the underlying snapshotter.
2. Similarly, if a DiffOp results in a single layer with deletions being mounted, include a temporary empty directory as an additional lowerdir, which allows you to use overlay instead of bind and thus properly hide whiteouts.
    1. This will need to be handled by all snapshotter methods that return mounts, not just Merge and Diff, so we need to modify some of the existing methods there too.
    2. As will be explained fully in the image export doc, we also need to make sure that these empty layers get included when exporting so that runtimes don’t experience the same problem when trying to use these images

# **Appendix**

## More LLB Examples

### Multiple Mounts
```
base := Image("base")
src := Git("github.com/foo/bar.git", "main")
run := base.Run(
    Shlex("make -C /src install"),
    AddMount("/src", src),
)

baseDiff := Diff(base, run.Root()) // Does NOT have changes made to /src

srcDiff := Diff(src, run.GetMount("/src")) // Has ONLY changes made to /src
```

Diff accepts args of type State, so when using it with Run you can’t just get the diff across every mount, you have to call Diff with the State of a specific mount from the Run.

### Deletions
```
base := Scratch().
  File(MkFile("/foo"))).
  File(MkFile("/bar")))

modified := base.
  File(MkFile("/qaz")).
  File(Rm("/bar"))

diff := Diff(base, modified) /* single layer, consists of:
  /qaz
	[delete /bar]
*/

Merge(base, diff) /* consists of:
	/qaz
	/foo
	[delete /bar]
*/
```

Here you can see that deletions are included with diffs and applied as expected during merges. It’s also possible for the base layer of states to have deletions in them.

An additional important note is that Diff is a function of the mounted views of lower and upper. The implication is that if lower and/or upper have whiteouts/opaques, those are not directly visible to the diff calculation because they disappear once mounted. For example (continuing from the code above):
```
base2 := Scratch().File(MkFile("/foo"))
diff2 := Diff(base2, diff) /* consists of:
	[delete /foo]
	/qaz
*/

Merge(base2, diff2) /* consists of:
	/qaz
*/
```

Note that diff2 does NOT contain `[delete /bar]` because it was not visible once diff was mounted. This is despite the fact that if you were to compare the underlying, unmounted changesets of base2 and diff, you’d see a difference of a whiteout file at `/bar`. This behavior was chosen because it feels more intuitive, but if some obscure need arises for the opposite behavior, it’s always possible to add an option to DiffOp for it.

## More Diff Efficiency Examples

In addition to the cases listed previously, some more worth mentioning are:
* `Diff(Scratch(), A)` **can** be done efficiently
    * This case is results in just `A`
* `Diff(A, A)` **can** be done efficiently
    * This case results in `Scratch()`
* `Merge(A, Diff(A, B))` is a case where the Diff can not be done efficiently, but the Merge can by using knowledge of how the Diff was constructed
    * The result in this case is just `B`, which means that even the non-overlay merge method can avoid copying for this merge.
    * This is an example of why we want to always save the "history" of the diffs/merges/etc. that construct a given ref in the cache package rather than just collapse it when we are forced to make new snapshots.
* `Diff(A->B, C->D)` can **not** be done efficiently
    * Even though `A->B` was the "original" ancestor of `C->D` in the full chain, `C->D` got diffed out, so now the diff must consist of the changes needed to not only “add” `C->D` but also delete `A->B`
* `Diff(A->B->C, A)` can **not** be done efficiently
    * The diff here consists of the "inverse" of `B->C`, that is, the changes needed to remove `B->C` and ensure any overwritten/deleted files/dirs in `A` are added back
