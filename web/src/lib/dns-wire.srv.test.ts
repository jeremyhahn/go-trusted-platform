import { describe, expect, it } from "vitest";
import type { Zone } from "trusted-platform-sdk";

import { readZoneDetail } from "./dns-wire";

describe("readZoneDetail SRV records (#2060)", () => {
  it("reads srvRecords as SRV rows with priority, weight and port", () => {
    const zone: Zone = {
      id: "9",
      name: "example.com.",
      ttl: 300,
      description: "",
      internal: true,
      records: {
        srvRecords: [
          {
            name: "_sip._tcp",
            target: "sip.example.com.",
            port: 5060,
            priority: 10,
            weight: 20,
            ttl: 300,
          },
        ],
      },
    };

    const detail = readZoneDetail(zone);

    expect(detail.records).toHaveLength(1);
    expect(detail.records[0]).toMatchObject({
      type: "SRV",
      name: "_sip._tcp",
      value: "sip.example.com.",
      ttl: 300,
      priority: 10,
      weight: 20,
      port: 5060,
    });
    expect(detail.recordCount).toBe(1);
  });
});
