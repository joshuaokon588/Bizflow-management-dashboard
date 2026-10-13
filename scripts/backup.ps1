param(
  [string]$BackupDirectory = ".\backups",
  [string]$Database = "bizflow"
)
$ErrorActionPreference = "Stop"
if (-not $env:DB_HOST) { throw "Set DB_HOST in your environment first." }
if (-not $env:DB_USER) { throw "Set DB_USER in your environment first." }
if (-not $env:DB_PASSWORD) { throw "Set DB_PASSWORD in your environment first." }
$dump = Get-Command mysqldump -ErrorAction SilentlyContinue
if (-not $dump) { throw "mysqldump was not found. Add MySQL Server's bin folder to PATH." }
New-Item -ItemType Directory -Force -Path $BackupDirectory | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$out = Join-Path $BackupDirectory "$Database-$stamp.sql"
$env:MYSQL_PWD = $env:DB_PASSWORD
try {
  & mysqldump --host=$env:DB_HOST --port=$(if($env:DB_PORT){$env:DB_PORT}else{'3306'}) --user=$env:DB_USER --single-transaction --routines --triggers --databases $Database --result-file=$out
  if ($LASTEXITCODE -ne 0) { throw "mysqldump failed with exit code $LASTEXITCODE" }
  Write-Output "Backup created: $out"
} finally { Remove-Item Env:\MYSQL_PWD -ErrorAction SilentlyContinue }
