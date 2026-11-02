# Platform declarations

`dotnet-8.0.json.z` summarizes the public declarations of the .NET 8
reference packs, for C# type inference ([ADR-0022](../../../docs/adr/0022-platform-types.md)):

- `Microsoft.NETCore.App.Ref` 8.0.11
- `Microsoft.AspNetCore.App.Ref` 8.0.11

Reference packs hold signatures only, no code. Both are MIT-licensed by the
.NET Foundation; the license is in `dotnet-8.0.LICENSE.txt`.

The file is generated, never edited: `tools/netref/regenerate.sh` downloads
the packs, checks their SHA-256, and runs the extractor in `tools/netref`.
The output is deterministic, so a regeneration from the same packs gives
the same bytes.
