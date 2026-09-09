/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        ink: "#e8eef8",
        muted: "#91a0b8",
        panel: "#111a2c",
        panel2: "#17233a",
        accent: "#5eead4",
        warn: "#fbbf24"
      }
    }
  },
  plugins: []
};
