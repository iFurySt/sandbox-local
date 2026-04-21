#!/usr/bin/env bash

set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist_dir="${repo_root}/dist"

rm -rf "${dist_dir}"
mkdir -p "${dist_dir}"

version="${VERSION:-dev}"
git_sha="${GITHUB_SHA:-$(git -C "${repo_root}" rev-parse HEAD 2>/dev/null || echo unknown)}"
generated_at="$(date -u +"%Y-%m-%dT%H:%M:%SZ")"

builds=(
  "darwin/arm64"
  "darwin/amd64"
  "linux/arm64"
  "linux/amd64"
  "windows/arm64"
  "windows/amd64"
)

artifacts=()

for target in "${builds[@]}"; do
  goos="${target%/*}"
  goarch="${target#*/}"
  name="sandbox-local_${version}_${goos}_${goarch}"
  binary="sandbox-local"
  if [[ "${goos}" == "windows" ]]; then
    binary="sandbox-local.exe"
  fi
  work_dir="${dist_dir}/${name}"
  mkdir -p "${work_dir}"
  (
    cd "${repo_root}"
    GOOS="${goos}" GOARCH="${goarch}" CGO_ENABLED=0 \
      go build \
        -ldflags "-s -w -X github.com/iFurySt/sandbox-local/internal/cli.version=${version}" \
        -o "${work_dir}/${binary}" \
        ./cmd/sandbox-local
  )
  cp "${repo_root}/LICENSE" "${work_dir}/LICENSE"
  cp "${repo_root}/README.md" "${work_dir}/README.md"
  mkdir -p "${work_dir}/configs/examples"
  cp "${repo_root}/configs/examples/default.yaml" "${work_dir}/configs/examples/default.yaml"
  archive="${dist_dir}/${name}.tar.gz"
  tar -czf "${archive}" -C "${dist_dir}" "${name}"
  rm -rf "${work_dir}"
  artifacts+=("$(basename "${archive}")")
done

cat > "${dist_dir}/release-manifest.json" <<EOF
{
  "repository": "${GITHUB_REPOSITORY:-local}",
  "git_sha": "${git_sha}",
  "version": "${version}",
  "generated_at_utc": "${generated_at}",
  "artifacts": [
$(printf '    "%s"' "${artifacts[0]}")
$(for artifact in "${artifacts[@]:1}"; do printf ',\n    "%s"' "${artifact}"; done)

  ]
}
EOF

echo "${dist_dir}"
