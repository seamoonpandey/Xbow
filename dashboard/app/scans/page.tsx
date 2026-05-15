import { ScansOverview } from "@/components/scans-overview";

export default function ScansPage() {
  return (
    <ScansOverview
      title="Scans"
      description="Browse and manage the complete scan queue in one workspace."
      showSummary={false}
      showDrawer={false}
      showClearAll={false}
    />
  );
}
