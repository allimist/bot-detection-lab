import type { WebRtcSignals } from '@bdl/scoring';

const PRIVATE = /^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.|fc|fd|fe80:|::1$)/i;

/**
 * Ask a STUN server what our public address is. A VPN or proxy that only covers HTTP
 * leaves this UDP path untouched, so the address here can differ from the one the server sees.
 */
export function webrtc(stun = 'stun:stun.l.google.com:19302', timeoutMs = 2500): Promise<WebRtcSignals> {
  const PC = window.RTCPeerConnection ?? (window as unknown as { webkitRTCPeerConnection?: typeof RTCPeerConnection }).webkitRTCPeerConnection;
  if (!PC) return Promise.resolve({ supported: false, publicIps: [], localIps: [], error: 'RTCPeerConnection is not available.' });

  return new Promise((resolve) => {
    const publicIps = new Set<string>();
    const localIps = new Set<string>();
    let pc: RTCPeerConnection;
    let finished = false;
    const finish = (error?: string) => {
      if (finished) return;
      finished = true;
      try { pc.close(); } catch { /* already closed */ }
      resolve({ supported: true, publicIps: [...publicIps], localIps: [...localIps], ...(error ? { error } : {}) });
    };
    try {
      pc = new PC({ iceServers: [{ urls: stun }] });
    } catch (e) {
      resolve({ supported: false, publicIps: [], localIps: [], error: String(e) });
      return;
    }
    pc.onicecandidate = (e) => {
      if (!e.candidate) return finish();
      // "candidate:842163049 1 udp 1677729535 84.229.10.20 54321 typ srflx raddr 0.0.0.0 rport 0 ..."
      const parts = e.candidate.candidate.split(' ');
      const address = parts[4] ?? '';
      const type = parts[parts.indexOf('typ') + 1];
      if (!address || address.endsWith('.local')) return;
      if (type === 'srflx' || (type === 'host' && !PRIVATE.test(address))) publicIps.add(address);
      else if (type === 'host') localIps.add(address);
    };
    pc.createDataChannel('bot-check');
    pc.createOffer()
      .then((offer) => pc.setLocalDescription(offer))
      .catch((e) => finish(String(e)));
    setTimeout(() => finish(), timeoutMs);
  });
}
