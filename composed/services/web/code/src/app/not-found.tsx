import Link from "next/link";

export default function NotFound() {
  return (
    <div className="flex min-h-screen flex-col items-center justify-center">
      <h1 className="text-6xl font-bold mb-4">404</h1>
      <p className="text-gray-500 mb-8">Page not found</p>
      <Link href="/" className="underline">Go home</Link>
    </div>
  );
}
