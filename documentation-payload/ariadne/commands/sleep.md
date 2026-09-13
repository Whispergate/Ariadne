+++
title = "sleep"
chapter = false
weight = 100
+++

## sleep

Update the beacon interval and jitter.

### Usage

```
sleep [interval_seconds] [jitter_percent]
```

Default jitter is 23%.

### Notes

The interval is in seconds and jitter is a percentage (0-100) applied as random variance around the interval.
