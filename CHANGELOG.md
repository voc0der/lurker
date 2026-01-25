# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## [Unreleased]

### Added
- Add /r/popular link to navigation menu (next to /r/all)
- High-resolution thumbnail support using Reddit preview images (like RES)
  - Uses preview.images API for 640x640+ quality instead of low-res 70x70 thumbnails
  - User preference toggle in dashboard (enabled by default)
  - Low-bandwidth option available by disabling high-res thumbnails
- New database migration for `highResThumbnails` user preference

### Changed
- Updated `postThumbnail()` function to accept user preference parameter
- Enhanced navigation header to include popular subreddit access
- Improved image quality across all post listings

### Technical
- Database migration: add-high-res-thumbnails-column
- Modified files: header.pug, postUtils.pug, post.pug, dashboard.pug, db.js, routes/index.js
