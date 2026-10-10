import { useEffect, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { CheckPage } from './CheckPage.tsx';
import { DashboardPage } from './DashboardPage.tsx';
import { EmbedPage } from './EmbedPage.tsx';
import './styles.css';

const PAGES = [
  { path: '/', label: 'Check me', Page: CheckPage },
  { path: '/dashboard', label: 'Dashboard', Page: DashboardPage },
  { path: '/embed', label: 'Embed & API', Page: EmbedPage },
];

function App() {
  const [path, setPath] = useState(location.pathname);
  useEffect(() => {
    const onPop = () => setPath(location.pathname);
    addEventListener('popstate', onPop);
    return () => removeEventListener('popstate', onPop);
  }, []);
  const go = (to: string) => (e: React.MouseEvent) => {
    if (e.metaKey || e.ctrlKey) return;
    e.preventDefault();
    history.pushState(null, '', to);
    setPath(to);
  };
  const current = PAGES.find((p) => p.path === path) ?? PAGES[0]!;
  return (
    <>
      <header className="topbar">
        <a className="brand" href="/" onClick={go('/')}>
          <img src="/favicon.svg" alt="" /> Bot Detection Lab
        </a>
        <nav>
          {PAGES.map((p) => (
            <a key={p.path} href={p.path} onClick={go(p.path)} className={p === current ? 'active' : ''}>{p.label}</a>
          ))}
        </nav>
        <a href="https://github.com/allimist/bot-detection-lab" className="small">GitHub</a>
      </header>
      <main>
        <current.Page />
      </main>
      <footer>
        Everything runs on this server: no third-party fingerprinting service. IP data: <a href="https://db-ip.com">DB-IP</a> (CC BY 4.0),{' '}
        <a href="https://github.com/X4BNet/lists_vpn">X4BNet lists</a>, Tor Project exit list.
      </footer>
    </>
  );
}

// No StrictMode: its double-mounted effects would run the bot check twice per page view.
createRoot(document.getElementById('root')!).render(<App />);
