import axe, { type AxeResults } from "axe-core";

/**
 * Run axe-core against a rendered container under jsdom. Colour-contrast needs
 * a real layout engine and is covered by the live-browser sweep instead, so it
 * is disabled here; everything else in WCAG 2.1 A/AA + best-practice runs.
 */
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
