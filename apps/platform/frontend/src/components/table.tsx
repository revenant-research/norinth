import { useMemo, useState } from "react";

export function formatTimestamp(value: unknown): string {
  if (!value) return "no activity";
  const parsed = new Date(String(value));
  if (Number.isNaN(parsed.getTime())) return String(value);
  return parsed.toLocaleString();
}

// a real table for tabular records: client-side sort and search over the
// loaded rows. server-side pagination and server-side filters stay with the
// caller; this component only presents what it is given. every column
// declares how it renders, sorts, and matches search, so views stay declarative
export type Column<Row> = {
  key: string;
  label: string;
  render?: (row: Row) => React.ReactNode;
  // value used for ordering; defaults to the row field named by `key`
  sortValue?: (row: Row) => string | number;
  // text used for search matching; defaults to the sort value as text
  searchValue?: (row: Row) => string;
  align?: "left" | "right";
  mono?: boolean;
  sortable?: boolean;
};

type SortState = { key: string; direction: "asc" | "desc" } | null;

function defaultValue<Row>(row: Row, key: string): string | number {
  const value = (row as Record<string, unknown>)[key];
  if (typeof value === "number") return value;
  return value === null || value === undefined ? "" : String(value);
}

export function DataTable<Row>({
  columns,
  rows,
  rowKey,
  empty,
  label,
  initialSort,
  searchable = true,
  serverTotal,
}: {
  columns: Array<Column<Row>>;
  rows: Row[];
  rowKey: (row: Row) => string;
  empty: string;
  // what one row is, for the count line ("entries", "traces")
  label: string;
  initialSort?: { key: string; direction: "asc" | "desc" };
  searchable?: boolean;
  // total on the server when the caller paginates; shown so "50 of 120" is honest
  serverTotal?: number;
}) {
  const [sort, setSort] = useState<SortState>(initialSort ?? null);
  const [search, setSearch] = useState("");

  const visible = useMemo(() => {
    let out = rows;
    const needle = search.trim().toLowerCase();
    if (needle) {
      out = out.filter((row) =>
        columns.some((column) => {
          const text = column.searchValue
            ? column.searchValue(row)
            : String(column.sortValue ? column.sortValue(row) : defaultValue(row, column.key));
          return text.toLowerCase().includes(needle);
        }),
      );
    }
    if (sort) {
      const column = columns.find((candidate) => candidate.key === sort.key);
      if (column) {
        const direction = sort.direction === "asc" ? 1 : -1;
        out = [...out].sort((a, b) => {
          const left = column.sortValue ? column.sortValue(a) : defaultValue(a, column.key);
          const right = column.sortValue ? column.sortValue(b) : defaultValue(b, column.key);
          if (typeof left === "number" && typeof right === "number") return (left - right) * direction;
          return String(left).localeCompare(String(right)) * direction;
        });
      }
    }
    return out;
  }, [rows, columns, search, sort]);

  function toggleSort(key: string) {
    setSort((current) => {
      if (!current || current.key !== key) return { key, direction: "asc" };
      if (current.direction === "asc") return { key, direction: "desc" };
      return null;
    });
  }

  const countParts = [`${visible.length} of ${rows.length} ${label}`];
  if (serverTotal !== undefined && serverTotal > rows.length) countParts.push(`${serverTotal} total`);

  return (
    <div className="data-table-block">
      <div className="data-table-toolbar">
        {searchable ? (
          <input
            type="search"
            className="data-table-search"
            placeholder={`Search ${label}`}
            aria-label={`Search ${label}`}
            value={search}
            onChange={(event) => setSearch(event.target.value)}
          />
        ) : null}
        <span className="data-table-count">
          {countParts.join(" · ")}
        </span>
      </div>
      {visible.length === 0 ? (
        <p className="data-table-empty">{search ? `No ${label} match "${search}".` : empty}</p>
      ) : (
        <div className="table-scroll">
          <table className="data-table">
            <thead>
              <tr>
                {columns.map((column) => {
                  const sortable = column.sortable !== false;
                  const active = sort?.key === column.key;
                  const ariaSort = active ? (sort?.direction === "asc" ? "ascending" : "descending") : "none";
                  return (
                    <th
                      key={column.key}
                      scope="col"
                      aria-sort={sortable ? ariaSort : undefined}
                      className={column.align === "right" ? "align-right" : undefined}
                    >
                      {sortable ? (
                        <button type="button" className="table-sort" onClick={() => toggleSort(column.key)}>
                          {column.label}
                          <span className="sort-mark" aria-hidden="true">
                            {active ? (sort?.direction === "asc" ? "▲" : "▼") : ""}
                          </span>
                        </button>
                      ) : (
                        column.label
                      )}
                    </th>
                  );
                })}
              </tr>
            </thead>
            <tbody>
              {visible.map((row) => (
                <tr key={rowKey(row)}>
                  {columns.map((column) => (
                    <td
                      key={column.key}
                      className={[
                        column.align === "right" ? "align-right" : "",
                        column.mono ? "mono" : "",
                      ].join(" ").trim() || undefined}
                    >
                      {column.render ? column.render(row) : String(defaultValue(row, column.key) || "")}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
