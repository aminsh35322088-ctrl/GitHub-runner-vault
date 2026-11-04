import { describe, expect, test } from 'vitest'
import {
  ORPHAN_SPAN_ANALYTICS,
  ORPHAN_SPAN_TO_SM,
  ORPHAN_SPAN_TO_XL,
  SUMMARY_GRID_3_SM,
  SUMMARY_GRID_3_XL,
  SUMMARY_GRID_4,
  SUMMARY_GRID_5,
} from './responsive.ts'

const GRIDS = {
  SUMMARY_GRID_4,
  SUMMARY_GRID_3_SM,
  SUMMARY_GRID_3_XL,
  SUMMARY_GRID_5,
} as const

describe('phone-first summary grid policy (issues #26/#27)', () => {
  test('every summary grid is a single column on phones', () => {
    for (const [name, classes] of Object.entries(GRIDS)) {
      expect(classes, name).toContain('grid-cols-1')
      // The base (unprefixed) column count must be 1: no grid may start at
      // grid-cols-2, which is what made phones render the desktop dashboard.
      const base = classes.split(' ').filter((token) => !token.includes(':'))
      expect(base, name).toContain('grid-cols-1')
      expect(base, name).not.toContain('grid-cols-2')
    }
  })

  test('two columns only begin at the 480px hinge', () => {
    for (const [name, classes] of Object.entries(GRIDS)) {
      expect(classes, name).toContain('min-[480px]:grid-cols-2')
    }
  })

  test('odd-count grids span their last card across the two-column range', () => {
    for (const span of [ORPHAN_SPAN_TO_SM, ORPHAN_SPAN_TO_XL, ORPHAN_SPAN_ANALYTICS]) {
      expect(span).toContain('min-[480px]:')
      expect(span).toContain('col-span-2')
      // The span must end before the grid gains a full row of columns,
      // otherwise the last card would stay double-width on desktop.
      expect(span).toMatch(/max-(sm|xl|2xl):col-span-2/)
    }
  })
})
