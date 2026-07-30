# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

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
