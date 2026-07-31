# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

## [0.2.3] - 2026-07-31

### Added

- Added RES-style discussion thumbnails for Reddit text posts: the main glyph
  opens the full post while a small expando toggles a formatted inline preview
- Added responsive, keyboard-accessible text previews to compact feeds, search
  results, crossposts, and posts loaded by infinite scroll

### Fixed

- Decode self-text in compact listings and nested crossposts so inline previews
  render formatted content instead of encoded markup

## [0.2.2] - 2026-07-30

### Fixed

- Fixed expanded Reddit videos failing in Vivaldi and Chromium-based mobile
  browsers that advertise unusable native HLS support
- Initialize DASH before expanded playback to retain audio, with automatic MP4
  recovery when adaptive playback fails
- Release the thumbnail decoder while a mobile video is expanded and restore
  thumbnail playback when it is closed
- Explicitly play only visible video thumbnails, pause offscreen videos, and
  initialize thumbnails added by infinite scroll
- Retry thumbnail playback with Reddit's alternate MP4 when the preferred
  quality cannot be decoded
- Keep cross-origin media and byte-range requests out of the app service
  worker's HTML/offline cache path

## [0.2.1] - 2026-07-30

### Changed

- Renamed the personalized subscription feed heading from `lurker` to `home`

## [0.2.0] - 2026-07-30

### Added

- Reddit-inspired responsive feed with right-aligned thumbnails, compact post
  metadata, action chips, and full-width expanded media
- Responsive app navigation and compact feed sorting/view controls
- Per-user Reddit auth settings in the dashboard for bearer tokens or cookie headers
- Add /r/popular link to navigation menu (next to /r/all)
- High-resolution thumbnail support using Reddit preview images (like RES)
  - Uses preview.images API for 640x640+ quality instead of low-res 70x70 thumbnails
  - User preference toggle in dashboard (enabled by default)
  - Low-bandwidth option available by disabling high-res thumbnails
- New database migration for `highResThumbnails` user preference

### Changed

- Updated light, dark, and automatic themes to use Reddit-inspired colors
- Centered the feed on desktop while keeping posts edge-to-edge on mobile
- Kept the optional classic layout compact on desktop without breaking expanded
  media
- Updated `postThumbnail()` function to accept user preference parameter
- Enhanced navigation header to include popular subreddit access
- Improved image quality across all post listings

### Fixed

- Fixed expanded videos breaking after Android browsers entered fullscreen
- Prepare HLS/DASH before mobile playback and automatically restore the fallback
  MP4 when DASH playback fails
- Fixed compact expanded media rendering beside and underneath post text instead
  of in a full-width row
- Pause expanded videos when their post is collapsed
- Video preview quality in compact view now uses fallback_url (full quality) instead of scrubber_url (low quality)
- Video previews now respect the same `highResThumbnails` user preference toggle
  - High-res enabled: uses fallback_url (full quality MP4)
  - High-res disabled: uses scrubber_url (low quality for bandwidth savings)
- Removed hardcoded 100px x 100px dimensions from video preview, now responsive via CSS

### Technical

- Added keyboard-accessible thumbnail expansion and semantic navigation markup
- Added local DASH playback support with a mobile-safe MP4 fallback
- Database migration: add-reddit-auth-headers-column
- Database migration: add-high-res-thumbnails-column
