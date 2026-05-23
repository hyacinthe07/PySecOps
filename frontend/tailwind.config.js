/** @type {import('tailwindcss').Config} */
module.exports = {
  content: ["./src/**/*.{js,jsx,ts,tsx}"],
  theme: {
    extend: {
      colors: {
        dark:    '#0d1117',
        card:    '#161b22',
        border:  '#30363d',
        cyber:   '#58a6ff',
        success: '#3fb950',
        danger:  '#f85149',
        warning: '#d29922',
        purple:  '#bc8cff',
        dim:     '#8b949e',
      },
    },
  },
  plugins: [],
}
