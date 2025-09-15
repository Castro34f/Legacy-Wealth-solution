function toggleMenu(){
  const m = document.getElementById('menu');
  m.classList.toggle('open');
}

/* ===== Canvas chart + polling (now with better status + slower polling) ===== */
(() => {
  let ctx, canvas, timer=null, data=[], minY=0, maxY=1, statusEl;
  let currentTicker='BTC';

  const COLORS = { grid:'rgba(255,255,255,0.08)', line:'#2eea8b' };

  function dprFix(c){
    const dpr = window.devicePixelRatio || 1;
    const rect = c.getBoundingClientRect();
    c.width  = Math.round(rect.width * dpr);
    c.height = Math.round(200 * dpr);
    c.style.height = '200px';
  }

  function setRange(){
    if (!data || data.length === 0){ minY=0; maxY=1; return; }
    minY = Math.min(...data);
    maxY = Math.max(...data);
    const pad = (maxY-minY)*0.1 || 1;
    minY -= pad; maxY += pad;
  }
  function yScale(v, h){ return h - ((v-minY)/(maxY-minY))*(h-20) - 10; }

  function draw(){
    const w = canvas.width, h = canvas.height;
    const n = data.length;
    const ctx2 = ctx;
    ctx2.clearRect(0,0,w,h);
    // grid
    ctx2.strokeStyle = COLORS.grid; ctx2.lineWidth = 1;
    for(let i=0;i<=4;i++){
      const y = 10 + (h-20)*(i/4);
      ctx2.beginPath(); ctx2.moveTo(0,y); ctx2.lineTo(w,y); ctx2.stroke();
    }
    if (n < 2) return;
    // line
    ctx2.strokeStyle = COLORS.line; ctx2.lineWidth = 2;
    ctx2.beginPath();
    for(let i=0;i<n;i++){
      const x=(w/(n-1))*i, y=yScale(data[i], h);
      if(i===0) ctx2.moveTo(x,y); else ctx2.lineTo(x,y);
    }
    ctx2.stroke();
  }

  async function fetchSpark(ticker){
    try{
      const r = await fetch(`/api/sparkline?ticker=${encodeURIComponent(ticker)}`, {cache:'no-store'});
      const j = await r.json();
      if (statusEl){
        statusEl.textContent = j.ok ? `Live data: ${j.ticker}` : `Using API failed: ${j.error || 'unknown'}`;
      }
      return (j.ok && Array.isArray(j.prices) && j.prices.length>0) ? j.prices : null;
    }catch(e){
      if (statusEl){ statusEl.textContent = `Network error`; }
      return null;
    }
  }

  async function refresh(){
    const series = await fetchSpark(currentTicker);
    if (series){
      data = series.slice(-120);
      setRange(); draw();
    }
  }

  function start(){
    stop();
    refresh();                             // immediate
    timer = setInterval(refresh, 10000);   // poll every 10s (kinder to APIs)
  }
  function stop(){ if (timer) clearInterval(timer); timer=null; }

  window.initAPILiveChart = (canvasId, ticker) => {
    currentTicker = ticker;
    canvas = document.getElementById(canvasId);
    statusEl = document.getElementById('chartStatus');
    if (!canvas) return;
    ctx = canvas.getContext('2d');
    dprFix(canvas);
    setRange(); draw();
    start();
    window.addEventListener('resize', () => { dprFix(canvas); setRange(); draw(); });
  };

  window.switchAPITicker = (ticker) => { currentTicker = ticker; refresh(); };
})();
// ===== Portfolio helpers =====
function polarToCartesian(cx, cy, r, angle) {
  const a = (angle - 90) * Math.PI / 180;
  return { x: cx + r * Math.cos(a), y: cy + r * Math.sin(a) };
}
function arcPath(cx, cy, r, startAngle, endAngle) {
  const start = polarToCartesian(cx, cy, r, endAngle);
  const end   = polarToCartesian(cx, cy, r, startAngle);
  const large = endAngle - startAngle <= 180 ? 0 : 1;
  return ["M", start.x, start.y, "A", r, r, 0, large, 0, end.x, end.y].join(" ");
}

window.initPortfolio = function(payload){
  // Donut
  const svg = document.getElementById("distDonut");
  if (svg) {
    const cx=100, cy=100, r=80;
    let start = 0;
    payload.distribution.forEach(seg=>{
      const end = start + (seg.percent/100)*360;
      const path = document.createElementNS("http://www.w3.org/2000/svg","path");
      path.setAttribute("d", arcPath(cx,cy,r,start,end));
      path.setAttribute("stroke", seg.color);
      path.setAttribute("stroke-width","20");
      path.setAttribute("fill","none");
      path.setAttribute("stroke-linecap","round");
      svg.appendChild(path);
      start = end;
    });
    // inner ring background
    const ring = document.createElementNS("http://www.w3.org/2000/svg","circle");
    ring.setAttribute("cx",cx); ring.setAttribute("cy",cy); ring.setAttribute("r",r-18);
    ring.setAttribute("fill","#ffffff");
    svg.appendChild(ring);
  }

  // Profit bars: set current vs deposited %
  const currentPct = Math.min(100, (payload.current / payload.deposited) * 100);
  const bar = document.getElementById("barCurrent");
  if (bar) bar.style.width = currentPct.toFixed(2) + "%";
};

// Mobile menu (already in your file, keep if exists)
window.toggleMenu = function(){
  const m = document.getElementById('menu');
  if (m) m.classList.toggle('open');
};