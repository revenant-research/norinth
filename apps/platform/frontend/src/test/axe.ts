// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Revenant Research

import axe, { type AxeResults } from "axe-core";

// run axe-core against a rendered container under jsdom. colour-contrast needs a
// real layout engine so it's disabled here and checked in the live-browser run;
// everything else in wcag 2.1 a/aa + best-practice runs
export async function runAxe(container: Element): Promise<AxeResults> {
  return axe.run(container, {
    runOnly: { type: "tag", values: ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "best-practice"] },
    rules: { "color-contrast": { enabled: false }, region: { enabled: false } },
  });
}

export function formatViolations(results: AxeResults): string {
  return results.violations
    .map((v) => `${v.id} (${v.impact}): ${v.help}\n  ${v.nodes.map((n) => n.target.join(" ")).join("\n  ")}`)
    .join("\n");
}
