# go-trusted-platform row table

One SPEC row = one row issue = one branch `row/<epic>-<slug>` = one lane
session = one PR (handbook `software/conventions/sdlc.md` §2b). Every open
issue is a row issue, sits under one, or is listed below as kept. The row's PR
closes its row issue and marks the row shipped in [docs/SPEC.md](../docs/SPEC.md).
Rows with no open work are not listed. Folded issues are closed and listed as a
checklist on their row issue.

## SPEC rows

| Row | Row issue | Status | Folded | Open PRs |
|---|---|---|---|---|
| web | #1665 | shipped | 73 | #1866, #1865, #1864, #1863, #1857, #1851, #1809, #1781, #1768, #1767, #1763, #1760, #1759, #1757, #1756, #1755, #1754, #1751, #1750, #1749, #1747, #1742, #1740, #1739, #1738, #1731, #1730, #1683, #1681, #1678, #1677, #1676, #1675 |
| attestation | #1686 | in progress | 6 | #1704, #1869 |
| auth | #646 | in progress | 10 | none |
| bootstrap | #1688 | in progress | 3 | none |
| daemon | #1689 | in progress | 8 | #1879 |
| device-enrollment | #1699 | in progress | 2 | none |
| factory-image | #669 | in progress | 0 | none |
| firmware | #773 | in progress | 0 | none |
| gateway | #1696 | in progress | 10 | #1716 |
| gateway-supervisor | #1193 | planned | 0 | none |
| installer | #1695 | in progress | 2 | none |
| ipxe | #1693 | in progress | 4 | none |
| luks | #1692 | in progress | 4 | none |
| policy-engines | #1691 | in progress | 0 | none |
| provisioning | #1694 | in progress | 4 | none |
| sdk | #1690 | in progress | 3 | #1882 |
| tenant | #301 | in progress | 1 | none |
| vpn | #1698 | in progress | 1 | #1717 |
| volume | #92 | planned | 2 | none |
| remote-deploy | #1700 | planned | 1 | none |
| pi-node-roles | #1701 | planned | 0 | none |
| ha-raft-template | #1702 | planned | 0 | #1867 |
| hsm-device-lifecycle | #886 | future | 0 | none |
| bmc | #239 | shipped | 0 | none |
| ca | #433 | shipped | 4 | none |
| cluster | #336 | shipped | 0 | none |
| device | #179 | shipped | 1 | none |
| dns | #956 | shipped | 0 | none |
| kms | #1436 | shipped | 0 | none |
| sdk-javascript | #248 | shipped | 0 | none |
| sdn | #732 | shipped | 0 | none |
| secrets | #62 | shipped | 0 | none |
| tpm | #684 | shipped | 3 | none |

## Seam rows (cross-repo)

| Seam | Row issue | Folded | Open PRs |
|---|---|---|---|
| ACME endpoint and test control plane for trusted-firmware#7 | #1095 | 0 | none |
| go-quicbaas and go-xkms to their upstream tags | #722 | 0 | none |

## Kept outside the rows

| Issue | Class | Why |
|---|---|---|
| #1388 | owner | Test-suite audit, ruling 273; not a SPEC row; #966 and #1121 folded in. PRs #1881 and #1454 fold into one PR |
| #705 | owner | Public-release readiness; docs/SPEC.md has no release row; #726, #835, #1439, #1441 folded in. PR #1868 |
| #1440 | owner | Rotate the GRUB signing key and re-sign the boot artifacts (owner via CA m2025) |
| #1419 | CI | CI Gate does not need the fips job |
| #1176 | main-fix | pkg/rpinetboot TestProbe_* time out under -race |

## Cross-row aggregates

#1853 (provisioning, devices and images, six rows) and #1852 (daemon and
platform services, five rows) carry members of several rows. Each row lands
through its own row PR; these branches stay as sources until their members are
carried.
