/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Poppins', 'system-ui', 'sans-serif'],
      },
      colors: {
        // Semantic Application Colors
        primary: 'var(--color-gray-dark)', // #2B2B2B - Used for main buttons, text
        secondary: 'var(--color-gray-medium)', // #B3B3B3 - Used for secondary text, icons
        
        // Backgrounds
        background: 'var(--bg-primary)',
        surface: 'var(--bg-secondary)',
        
        // Text
        main: 'var(--text-primary)',
        muted: 'var(--text-secondary)',
        inverted: 'var(--text-inverted)',
        
        // Borders
        border: 'var(--border-primary)',
        
        // Raw Palette
        gray: {
          light: 'var(--color-gray-light)', // #D4D4D4
          medium: 'var(--color-gray-medium)', // #B3B3B3
          dark: 'var(--color-gray-dark)', // #2B2B2B
          white: 'var(--color-white)', // #FFFFFF
        },

        // Universal Status Colors
        info: {
          DEFAULT: 'var(--color-info)',
          light: '#60A5FA',
          dark: '#2563EB',
        },
        success: {
          DEFAULT: 'var(--color-success)',
          light: '#4ADE80',
          dark: '#16A34A',
        },
        warning: {
          DEFAULT: 'var(--color-warning)',
          light: '#FACC15',
          dark: '#CA8A04',
        },
        error: {
          DEFAULT: 'var(--color-error)',
          light: '#F87171',
          dark: '#DC2626',
        },
      },
      borderColor: {
        DEFAULT: 'var(--border-primary)',
      },
    },
  },
  plugins: [],
}