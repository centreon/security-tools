#!/bin/bash

#---
## {Format messages}
#----
function success_output() {
 echo -e "\n\e[32m\e[1m$1\e[0m\t$2"
}
function error_output() {
  echo -e "\n\e[31m\e[1m$1\e[0m\t$2"
}
function query_output() {
  echo -e "\n\e[34m\e[1m$1\e[0m\t$2"
}
function divider_space() {
# Empty line ;)
  echo -e ""
}

ERROR_LOG="error_log.txt"
DEP_LIST="blacklist/compromised-packages.txt"
LOCKFILES=($(find ./ -name "package-lock.json" -o -name "pnpm-lock.yaml" -o -name "yarn.lock"))
COUNT=0

function setupErrorLogFile() {
  if [ -n "$ERROR_LOG" ]; then rm -f "$ERROR_LOG"; fi
  if [ ! -w "$ERROR_LOG" ]; then touch "$ERROR_LOG"; fi
}

function checkPnpmLockfile() {
  # Find dependency formated as
  # "name@version:"
  if grep -qF "$NAME@$VERSION" "$LOCKFILE"; then
    error_output "$NAME:$VERSION" "Was found in $LOCKFILE"
    echo "::error:: $NAME:$VERSION Was found in $LOCKFILE" >> "$ERROR_LOG"
  else
      echo -n "."
  fi
}

function checkNpmLockfile() {
  # Find dependencies formated as
  # "@accordproject/concerto-linter-default-ruleset": {
  #      "version": "3.24.1",
  local package="$1"
  local version="$2"
  local extractedDep

  extractedDep=$(awk -v name="$package" -v version="$version" '
    /"dependencies": *{/ { in_deps=1; next }
    in_deps && /"[^"]+": *{/ {
      match($0, /"([^"]+)": *{/, arr)
      dep = arr[1]
      getline
      if ($0 ~ /"version":/) {
        match($0, /"version": *"([^"]+)"/, ver)
        if (dep == name && ver[1] == version) {
          print dep " " ver[1]
        }
      }
    }
    ' "$LOCKFILE"
  )
  if [[ "$extractedDep" == "$package $version" ]]; then
    error_output "$package:$version" "Was found in $LOCKFILE"
    echo "::error:: $package:$version Was found in $LOCKFILE" >> "$ERROR_LOG"
  else
      echo -n "."
  fi
}

function checkYarnLockfile() {
  # Find dependencies formated as
  # "@aashutoshrathi/word-wrap@^1.2.3":
  #    version "1.2.6"

  local package="$1"
  local version="$2"
  local extractedDep

  extractedDep=$(awk -v pkg="$package" '
      /^".*":$/ {
        split($0, arr, ",")
        dep=arr[1]
        gsub(/"/, "", dep)
        sub(/@[^@]*$/, "", dep)
        current_pkg=dep
      }
      /version "/ {
        match($0, /"([^"]+)"/, v)
        if(current_pkg==pkg) print current_pkg, v[1]
      }
    ' "$LOCKFILE")
  if [[ "$extractedDep" == "$package $version" ]]; then
    error_output "$package:$version" "Was found in $LOCKFILE"
    echo "::error:: $package:$version Was found in $LOCKFILE" >> "$ERROR_LOG"
  else
      echo -n "."
  fi
}

function checkManifest() {
  success_output "Testing manifest = $LOCKFILE"
  manifest_type=$(basename "$LOCKFILE")

  while IFS=':' read -r NAME VERSION; do
    # ignorer lignes vides ou commentaires
    [[ -z "${NAME// }" ]] && continue
    [[ "$NAME" =~ ^# ]] && continue
    #query_output "DEBUG" "To find $NAME $VERSION"
    case "$manifest_type" in
      "pnpm-lock.yaml")
        checkPnpmLockfile
        ;;
      "yarn.lock")
        checkYarnLockfile "$NAME" "$VERSION"
        ;;
      "package-lock.json")
        checkNpmLockfile "$NAME" "$VERSION"
        ;;
      "*")
        error_output "KO" "Package not managed"
        exit 1
    esac
    COUNT=$((COUNT+1))
  done < "$DEP_LIST"
  query_output "Scanned" "$COUNT IOC"
}

setupErrorLogFile
for LOCKFILE in "${LOCKFILES[@]}"; do
  checkManifest "$LOCKFILE"
done
if [ -n "$ERROR_LOG" ]; then
  error_output "FATAL" "Breaking the run as following dependencies were found:"
  divider_space
  cat "$ERROR_LOG"
  exit 1
fi
