import { useState, useEffect } from 'react';

type Breakpoint = 'xs' | 'sm' | 'md' | 'lg' | 'xl' | '2xl';

const breakpoints: Record<Breakpoint, number> = {
  xs: 0,
  sm: 640,
  md: 768,
  lg: 1024,
  xl: 1280,
  '2xl': 1536,
};

export function useBreakpoint() {
  const [breakpoint, setBreakpoint] = useState<Breakpoint>('lg');
  const [isMobile, setIsMobile] = useState(false);
  const [isTablet, setIsTablet] = useState(false);
  const [isDesktop, setIsDesktop] = useState(true);

  useEffect(() => {
    const handleResize = () => {
      const width = window.innerWidth;
      
      if (width < breakpoints.sm) {
        setBreakpoint('xs');
        setIsMobile(true);
        setIsTablet(false);
        setIsDesktop(false);
      } else if (width < breakpoints.md) {
        setBreakpoint('sm');
        setIsMobile(true);
        setIsTablet(false);
        setIsDesktop(false);
      } else if (width < breakpoints.lg) {
        setBreakpoint('md');
        setIsMobile(false);
        setIsTablet(true);
        setIsDesktop(false);
      } else if (width < breakpoints.xl) {
        setBreakpoint('lg');
        setIsMobile(false);
        setIsTablet(false);
        setIsDesktop(true);
      } else if (width < breakpoints['2xl']) {
        setBreakpoint('xl');
        setIsMobile(false);
        setIsTablet(false);
        setIsDesktop(true);
      } else {
        setBreakpoint('2xl');
        setIsMobile(false);
        setIsTablet(false);
        setIsDesktop(true);
      }
    };

    handleResize();
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  return {
    breakpoint,
    isMobile,
    isTablet,
    isDesktop,
    isAbove: (bp: Breakpoint) => breakpoints[breakpoint] >= breakpoints[bp],
    isBelow: (bp: Breakpoint) => breakpoints[breakpoint] < breakpoints[bp],
  };
}

export function useMediaQuery(query: string): boolean {
  const [matches, setMatches] = useState(false);

  useEffect(() => {
    const media = window.matchMedia(query);
    if (media.matches !== matches) {
      // eslint-disable-next-line react-hooks/set-state-in-effect -- Sync with media query state
      setMatches(media.matches);
    }
    
    const listener = () => setMatches(media.matches);
    media.addEventListener('change', listener);
    return () => media.removeEventListener('change', listener);
  }, [matches, query]);

  return matches;
}
