# Partition identity (PARTUUID / filesystem UUID)

Questions like "the last 8 characters of partition `sda3`'s PARTUUID" require reading the partition table identity, not the filesystem UUID.

## Get PARTUUID

```bash
blkid /dev/sda3
# or list everything:
blkid
```

Sample output:

```text
/dev/sda3: UUID="xxxx-xxxx-..." PARTUUID="aaaabbbb-cccc-dddd-eeee-ffff00001122" TYPE="ext4"
```

- `UUID=` is the **filesystem** UUID (created when the filesystem was formatted).
- `PARTUUID=` is the **partition** UUID (from the partition table — GPT or the MBR pseudo-UUID).

The question asks for the partition's PARTUUID. Do not return the filesystem `UUID`.

## Derive "last 8 characters"

The PARTUUID is hyphen-separated. Strip the hyphens, take the final 8 hex digits, and apply the requested case. Illustrative (synthetic) value:

```bash
blkid /dev/sda3 -o value | tail -1        # just the PARTUUID
# PARTUUID=aaaabbbb-cccc-dddd-eeee-ffff00001122
# strip dashes: aaaabbbbccccddddeeeeffff00001122
# last 8 hex :                              00001122
echo "aaaabbbb-cccc-dddd-eeee-ffff00001122" | tr -d '-' | tail -c 9
# -> 00001122  (uppercase if the answer format requires it: 00001122)
```

When the format says "letters uppercase", emit the hex in upper case. Always show the rule you applied so the answer is reproducible.

## Which partition

Confirm the device name. `lsblk` maps `sda3` → mountpoint/type. If the question names a partition by label or mount, resolve it to the device first (`blkid -L <label>`, or `lsblk -o NAME,MOUNTPOINT,PARTLABEL`).
