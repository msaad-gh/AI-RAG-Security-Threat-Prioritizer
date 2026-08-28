import "./globals.css"

export const metadata = {
  title: "ThreatIQ - AI Security Operations",
  description: "Intelligent threat detection and incident response platform",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en">
      <body className="bg-gray-50 min-h-screen">
        <nav className="bg-white border-b px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 bg-blue-600 rounded flex items-center justify-center">
                <span className="text-white font-bold">T</span>
              </div>
              <h1 className="text-xl font-bold">ThreatIQ</h1>
            </div>
            <div className="flex space-x-4">
              <a href="/" className="text-gray-600 hover:text-gray-900">Dashboard</a>
              <a href="/incidents" className="text-gray-600 hover:text-gray-900">Incidents</a>
              <a href="/search" className="text-gray-600 hover:text-gray-900">Search</a>
            </div>
          </div>
        </nav>
        {children}
      </body>
    </html>
  )
}