# SteamHookTest

This is a simple test project to demonstrate how to bypass Steam for Kirikiri games.

## Prerequisites

* Steam DRM free Kirikiri games (use Steamless or similar tools)
* detours.lib

## How does it work?

The project is based on Detours and dll hijacking.

It hooks `FindResourceW`, `SizeOfResource` and `LoadResource` functions to find and edit the loaded resource data in memory instead of edit game executable directly. Hopefully, this will bypass the integrity check (`Malformed exe/dll detected`).

## Tested games

* [x] ATRI -My Dear Moments- (Steam version)