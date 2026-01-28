#!/bin/bash

OUTPUT="project.txt"
rm -f "$OUTPUT"

{
  echo "/*"
  echo "LANGUAGE: Go 1.25.5"
  echo "ARCHITECTURE: Hexagonal Architecture"
  echo "*/"
} >> "$OUTPUT"

# === ROOT FILES ===
ROOT_FILES=(
  ".github/copilot-instructions.md"
  "go.mod"
  "Makefile"
  "Dockerfile"
  "docker-compose.yml"
  ".env.docker"
  ".env"
  ".dockerignore"
  ".gitignore"
  "README.md"
)

for file in "${ROOT_FILES[@]}"; do
  if [ -f "./$file" ]; then
    echo -e "\n// FILE: ./$file" >> "$OUTPUT"
    cat "./$file" >> "$OUTPUT"
  fi
done

# === DIRECTORIES ===
for DIR in \
  pkg \
  internal \
  tests \
  cmd
do
  if [ -d "./$DIR" ]; then
    find "./$DIR" -type f -name "*.go" -print0 | while IFS= read -r -d '' file; do
      echo -e "\n// FILE: $file" >> "$OUTPUT"
      cat "$file" >> "$OUTPUT"
    done
  fi
done
