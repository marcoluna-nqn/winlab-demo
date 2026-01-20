# WinLab Release Notes

Release summary:
- WinLab is a local sandbox pipeline using Microsoft Defender plus isolation and reporting.
- This release hardens launcher/presets, improves purchase funnel copy, and ships release packaging.

Highlights:
- Launcher stages the pack in `C:\WinLab_Pack` to avoid space-related path failures.
- AUTO presets map pack/inbox/outbox and run the pipeline reliably.
- Pricing funnel includes WhatsApp fallback and delivery/requirements sections.

Artifacts (dist):
- `dist/winlab_site.zip`
- `dist/WinLab_ProductPack_0.8.0.zip`
- `dist/SHA256SUMS.txt`

SHA256:
```
e6e361ed91cd130fbfcf70315cb687e49d20832cc1af842cebe9f5b3cf740bba  dist/winlab_site.zip
237c67e5356664a3cc5cf4dc3c4f11ee6b16466b7a87803f2a6b7cdc0404784a  dist/WinLab_ProductPack_0.8.0.zip
10e3d61172a32c2535cb8787c53f4de0687878a0e5e64a865caa214d298d531f  downloads/WinLab_Setup_v0.8.0.zip
```
