# Release Process

The security-profiles-merger is released on an as-needed basis. The process is
as follows:

1. An issue is proposing a new release with a changelog since the last release
1. All [OWNERS](OWNERS) must LGTM this release
1. An OWNER runs `git tag -s $VERSION` and inserts the changelog, then pushes
   the tag with `git push <remote> $VERSION`, where `<remote>` is the
   kubernetes-sigs repository, not a fork
1. Pushing the tag triggers a GitHub Actions workflow that runs goreleaser to
   build binaries, generate cosign-signed checksums, SBOMs (via syft), and
   build provenance attestations
1. The release issue is closed
