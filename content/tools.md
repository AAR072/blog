---
title: "Tools"
description: "Offline tools for analyzing Vidar Stealer 3.2 samples and related artifacts."
hideMeta: true
ShowToc: false
ShowPostNavLinks: false
noComments: true
---

## vidar32-toolkit

[vidar32-toolkit](https://github.com/AAR072/vidar32-toolkit) is a focused analysis toolkit for Vidar Stealer 3.2. It extracts and decrypts the sample’s fixed-field configuration, fingerprints configurations, scans related artifacts, summarizes PCAPs, and decodes collected `ENC:` dead-drop records.

Use it to compare campaign configurations and examine related artifacts without running the stealer. Local analysis works offline by default; retrieving public dead-drop content is a separate, explicit option.

For the configuration layout, dead-drop behavior, and protocol context, see the [Vidar Stealer 3.2 research analysis](/research/vidar-stealer-3-2/).
