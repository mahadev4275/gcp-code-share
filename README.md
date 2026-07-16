# Running bdd  test

make sure PROJECT_ID env var is exported
```sh
export PROJECT_ID=gcp_project_id
```

run go test and point it to a tagged feature
```sh
go test -v tests/  -godog.tags="@your_tag_here"
```
