// Page-width hero with an ASCII VideoBackgroundShader, serif title, and two CTAs.
'use client'

import { useEffect, useState, useSyncExternalStore } from 'react'
import { VideoBackgroundShader } from '@holocron.so/vite/mdx'
import { buttonVariants } from './ui/button.tsx'

const HERO_FONT = "'IvarText', serif"
const GITHUB_URL = 'https://github.com/remorses/sigillo'

// Shader color is a WebGL uniform, so CSS dark: variants cannot reach it.
// Colors sit close to the page background so the title keeps contrast.
const DOT_COLOR_LIGHT = '#72c29c'
const DOT_COLOR_DARK = '#4a9a75'

function subscribeToThemeClass(onChange: () => void) {
  const observer = new MutationObserver(onChange)
  observer.observe(document.documentElement, { attributes: true, attributeFilter: ['class'] })
  return () => observer.disconnect()
}

function GitHubIcon({ className }: { className?: string }) {
  return (
    <svg className={className} viewBox='0 0 24 24' fill='currentColor'>
      <path d='M12 .5C5.65.5.5 5.65.5 12c0 5.08 3.29 9.39 7.86 10.91.58.1.79-.25.79-.56v-2c-3.2.7-3.87-1.37-3.87-1.37-.52-1.33-1.28-1.69-1.28-1.69-1.04-.71.08-.7.08-.7 1.15.08 1.76 1.18 1.76 1.18 1.03 1.76 2.69 1.25 3.35.96.1-.74.4-1.25.73-1.54-2.55-.29-5.24-1.28-5.24-5.69 0-1.26.45-2.28 1.18-3.08-.12-.29-.51-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.62 1.59.23 2.76.11 3.05.74.8 1.18 1.82 1.18 3.08 0 4.42-2.69 5.39-5.25 5.68.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.51 11.51 0 0 0 23.5 12C23.5 5.65 18.35.5 12 .5z' />
    </svg>
  )
}

export function HeroSection() {
  const [fontsReady, setFontsReady] = useState(false)
  const isDark = useSyncExternalStore(
    subscribeToThemeClass,
    () => document.documentElement.classList.contains('dark'),
    () => false,
  )

  useEffect(() => {
    const timeout = setTimeout(() => setFontsReady(true), 3000)
    void document.fonts.ready.then(() => setFontsReady(true))
    return () => clearTimeout(timeout)
  }, [])

  return (
    <div className='relative mt-4 lg:mt-8 mb-6 lg:mb-10 w-full rounded-xl flex flex-col items-center overflow-hidden'>
      <VideoBackgroundShader
        src='/assets/hero-bg.mp4'
        className='absolute inset-0 w-full h-full'
        dotStyle='ascii'
        dotColor={isDark ? DOT_COLOR_DARK : DOT_COLOR_LIGHT}
        dotSize={9}
        minDotSize={1}
        dotMargin={1}
        animSpeed={3}
        gamma={0.8}
        enableMask={false}
        fluidStrength={0.2}
        fluidCurl={80}
      />

      {/* Soft background scrim behind the title/CTAs so text stays readable over glyphs */}
      <div
        aria-hidden
        className='absolute inset-0 z-[1] pointer-events-none'
        style={{
          background:
            'radial-gradient(ellipse 45% 40% at 50% 42%, color-mix(in srgb, var(--background) 85%, transparent) 0%, color-mix(in srgb, var(--background) 60%, transparent) 50%, transparent 100%)',
        }}
      />

      <div
        className='relative z-[2] flex flex-col items-center justify-center text-center max-w-[820px] w-full px-5 pt-16 sm:pt-24 pb-20 lg:pb-[160px] gap-6'
        style={{
          opacity: fontsReady ? 1 : 0,
          transition: 'opacity 0.3s cubic-bezier(0.23, 1, 0.32, 1)',
        }}
      >
        <h1
          className='flex flex-col items-center leading-none text-[36px] sm:text-[44px] md:text-[52px] text-foreground'
          style={{ fontFamily: HERO_FONT }}
        >
          <span>Secrets manager,</span>
          <span>open source Doppler alternative</span>
        </h1>

        <div className='flex gap-3 flex-wrap justify-center'>
          <a href='/login?redirect=/dash' className={buttonVariants({ size: 'lg', className: 'no-underline gap-2.5' })}>
            <GitHubIcon className='size-[16px]' />
            Login with GitHub
          </a>
          <a
            href={GITHUB_URL}
            target='_blank'
            rel='noopener noreferrer'
            className={buttonVariants({ variant: 'ghost', size: 'lg', className: 'no-underline' })}
          >
            GitHub Repo ↗
          </a>
        </div>
      </div>
    </div>
  )
}
