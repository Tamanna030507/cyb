/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  theme: {
    extend: {
      colors: {
        surface: {
          950: "#0f1419",
          900: "#151b24",
          800: "#1a2332",
          700: "#243044",
          600: "#2d3a50"
        },
        ink: {
          100: "#e8eef7",
          200: "#c5d0e0",
          300: "#8b9bb5",
          400: "#6b7c96"
        },
        accent: {
          DEFAULT: "#3b82c4",
          soft: "#2a5a8a"
        },
        sev: {
          critical: "#c45c5c",
          high: "#d4893b",
          medium: "#c9a227",
          low: "#5b7c99"
        }
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"]
      }
    }
  },
  plugins: []
}