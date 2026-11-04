/**
 * Phone-first layout policy for summary/metric grids.
 *
 * Breakpoint contract (see issues #26/#27): below 480px every summary grid is
 * a single column — a phone never gets the desktop KPI row at half scale.
 * At 480px two columns fit comfortably; wider steps (sm/xl/2xl) then add
 * columns for tablets and desktops. Data text in these grids is never
 * smaller than `text-xs` (12px) and values are never truncated.
 *
 * The last card of an odd-count grid must not sit alone at half width in the
 * two-column range: it spans both columns there (ORPHAN_SPAN_* below) and
 * returns to a single column once the grid has enough columns per row.
 */

/** Overview + validation summaries: 1 → 2 (≥480px) → 4 (xl). */
export const SUMMARY_GRID_4 = 'grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 xl:grid-cols-4'

/** Requests + audit summaries: 1 → 2 (≥480px) → 3 (sm). */
export const SUMMARY_GRID_3_SM = 'grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 sm:grid-cols-3'

/** Integrations summary: 1 → 2 (≥480px) → 3 (xl). */
export const SUMMARY_GRID_3_XL = 'grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 xl:grid-cols-3'

/** Analytics summary: 1 → 2 (≥480px) → 3 (sm) → 4 (lg) → 5 (2xl). */
export const SUMMARY_GRID_5 = 'grid grid-cols-1 gap-3 min-[480px]:grid-cols-2 sm:grid-cols-3 lg:grid-cols-4 2xl:grid-cols-5'

/** Last card of a 3-card grid: spans the two-column range that ends at sm. */
export const ORPHAN_SPAN_TO_SM = 'min-[480px]:max-sm:col-span-2'

/** Last card of a 3-card grid: spans the two-column range that ends at xl. */
export const ORPHAN_SPAN_TO_XL = 'min-[480px]:max-xl:col-span-2'

/** Last card of the 5-card analytics grid: lone in the 2-col and 4-col ranges. */
export const ORPHAN_SPAN_ANALYTICS = 'min-[480px]:max-sm:col-span-2 lg:max-2xl:col-span-2'
