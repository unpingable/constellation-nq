# Passive enabled operational-pilot deployment supplement

Recorded: 2026-08-26T22:04:10Z

Classification: **ENABLED BOUNDED PASSIVE OPERATIONAL CONTINUITY QUALIFIED IN PRACTICE — LIVE OFFICE DORMANT**

This supplement appends to the passive sampling and operational-continuity
receipts. Detailed interpretation is in
[`PASSIVE_LOAD_ENABLED_PILOT_2026-08-26.md`](../../../docs/PASSIVE_LOAD_ENABLED_PILOT_2026-08-26.md).

## Charter and grants

- charter: `pilot:105d3b28-5181-4883-8d2f-a0804c327a7c`
- charter SHA-256:
  `745d21d689d52122b2bdccc30a27ddd99b221feaae64013c36dcc27342db24a4`
- governed subject: `host:labelwatch-host`
- G5:
  `sha256:d3e8aa2c540cc8e503a6010686e3ab98ea3591b4738ecd69faf01722f77df034`
- G6:
  `sha256:b6e813e4751604f015780d5f653596eccb2aaa636d8ac59e8550f3088582123a`
- E1:
  `sha256:41cf66b67a24a03c7e21849d727a231d3272e209eafe0c584b34929617657667`
- E2:
  `sha256:b7ffd88d1c87f05c5f690ef6bc20e7f290c3132aad860142b6cd3036505c0aa5`
- sampling cadence: 15 seconds
- diagnostic recurrence cadence: five minutes
- chartered window: 21:35Z through exclusive 22:03Z
- retention: finite `retain_all`

## Live custody

G5 produced 36 samples and expired. G6 produced 53 samples and expired. A
planned process restart preserved a gap from the final 21:43:15Z G5 sample to
the next real 21:45:26.744Z sample.

Exact successful diagnostic artifacts:

- G5 genesis:
  `sha256:813253f3ced94b1158a0bcc802b2ef04b9edfe1f38c0097f72508b30a3f782f1`
- G6 genesis:
  `sha256:859b6bcd73ce1ebda746a37d7cfc0b379f9073f550a2872ea3b810983db8b36a`
- E2 slot 1:
  `sha256:f1d1918a681be7ee9e957acda63b926168c73d1e82dda218787e3adb1cdaaedf`

The gap occurrence E1 slot 1 persisted governed refusal artifact
`sha256:1d7d17fe2d78aba220a9f7aaadab0cf7df56a3c831405f177d342171df400451`.
Its required input was absent because the newest pre-gap sample was about 57
seconds old against a 30-second maximum. No claim or helper fallback was
created.

E1 slot 0 and E2 slot 0 exhausted their two bounded pre-provider attempts while
genesis ordering was incomplete. Neither crossed the provider fence. The
history is retained as an operational ordering defect, not rewritten.

The final successful E2 acquisition was
`recurrence:b5c607dcceeee20233b43a9a1dcd297c2e4ab2f53fe02c989623b257b5f9a6c1`,
epoch 2. It selected G6 sequence 30 at 21:57:00Z and began at
21:57:09.032Z, leaving 20.968 seconds of eligibility margin.

## Storage

- G5: 46,175 sample bytes / 82,925 total store bytes
- G6: 67,945 sample bytes / 133,500 total store bytes
- total samples: 89
- exact samples selected by successful diagnostics: 3
- other samples not selected by those diagnostics: 86
- NQ office growth: 288,658 bytes
- conservative combined observed rate: about 1.08 MiB/hour
- final free bytes: 27,681,222,656
- required free-space floor: 10,737,418,240
- archive standing: not required for the recommended 24-hour next horizon

## Close state

- observer service: static/inactive
- recurrence service: static/inactive
- recurrence timer: disabled/inactive
- `nqd`: inactive
- G5/G6: expired; restart produced zero samples
- E1/E2: expired with zero remaining authority; wakeup produced zero new
  acquisitions
- Nightshift database SHA-256:
  `35818b7eafc0070489635e993d236754a9460713e272522ce6805c8eacb7c4c2`
- Nightshift cycles: 2 before and after
- final NQ database SHA-256:
  `c4a4c9864ff74c456798cf6f6339841919601c5319c96e9e1e1359275b7b08f3`

A4 remains outcome unknown, provider activity unknown, and fenced in
`linode:labelwatch-host` at epoch 1. A5 was not created.

## Operational decision

Enabled bounded operation is qualified in practice. The current 15-minute G
and 10-minute E limits are not sane manual production cadence: exact
provider-bound renewal requires configuration, a first sample, admission,
genesis, policy/enrollment custody, and timer selector activation in order.

The next reviewed operating-profile candidate is 15-second sampling,
five-minute diagnostics, six-hour finite G/E grants, and a 24-hour review
horizon. Those longer deployment bounds are not yet qualified. The pilot
justifies a focused campaign for a finite higher-level operating grant; it does
not justify automatic or recursive renewal.

