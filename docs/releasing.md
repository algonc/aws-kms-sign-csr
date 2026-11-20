# Releasing aws-kms-sign-csr

The GitHub Actions workflow in `.github/workflows/release.yml` builds and publishes releases when a version tag is pushed.

## Versioning

Use a new `vMAJOR.MINOR.PATCH` tag for each stable release, such as `v1.2.0`. A suffix such as `v1.2.0-rc.1` creates a GitHub prerelease and keeps it from being marked as the latest release.

Keep each pushed version tag on its original commit. If released code needs a correction, commit the fix and publish a new version.

## Prepare the Release

These steps require Git, GNU Make, and Go 1.26.0 or later.

1. Confirm that `main` contains the intended changes and that CI has passed for the commit you plan to tag. Update user documentation for any behavior changes.
2. Tidy the Go module and check whether its dependency files need to be committed.

   ```sh
   make tidy
   git diff --exit-code -- go.mod go.sum
   ```

3. Verify dependencies, run vet, and run the tests.

   ```sh
   make verify vet test
   ```

4. Confirm that you are on `main` and the working tree is clean.

   ```sh
   git status --short --branch
   ```

## Publish the Release

From the commit you verified on `main`, create and push an annotated version tag. Replace `v1.2.0` with the version you are releasing.

```sh
git tag -a v1.2.0 -m "Release v1.2.0"
git push origin v1.2.0
```

The Release workflow verifies dependencies, runs tests and vet on Linux, macOS, and Windows, and runs the race detector on Linux. It then builds AMD64 and ARM64 binaries for all three platforms. Each archive includes the executable, `LICENSE`, `README.md`, and `docs/`.

Assets follow the pattern `aws-kms-sign-csr_<tag>_<os>_<arch>`, where the OS is `linux`, `darwin`, or `windows`. Linux and macOS assets use `.tar.gz`, and Windows assets use `.zip` and contain `aws-kms-sign-csr.exe`. The workflow generates `checksums.txt`, verifies the SHA-256 checksums before publishing, and creates the GitHub release with automatically generated notes.

## Verify the Release

1. Confirm that the GitHub release has all six platform archives and `checksums.txt`.
2. Download `checksums.txt` and at least one archive for your platform to the same directory. On Linux, run the following and look for `OK` next to each downloaded archive.

   ```sh
   sha256sum --check --ignore-missing checksums.txt
   ```

3. Extract the archive and run `./aws-kms-sign-csr -help` or `.\aws-kms-sign-csr.exe -help` on Windows. Expect the CLI to print its usage and exit with status `1`.
4. Review the generated release notes before announcing the release.

For a temporary workflow failure, check whether the release already exists. If publication has yet to occur, rerun the failed jobs in GitHub Actions. If a code or packaging change is required, commit the correction and publish a new version tag.
