// Premium horizontal carousel for browsing the example policy profiles —
// the one place a carousel genuinely helps (spec §12 "Premium carousel
// specification"). Pointer-capture drag with 1:1 tracking, release velocity
// handed to a critically-damped spring, momentum projection to pick the
// landing snap point, interruptible/reversible mid-motion, a visible partial
// next-item affordance, keyboard + accessible prev/next, and
// prefers-reduced-motion support. No autoplay.
//
// Motion model: the track is moved with `transform: translateX` driven by a
// rAF spring (not native scroll), so gestures are smooth, interruptible and
// reversible. The `.rs-carousel` view clips the track (overflow hidden) and
// shows a partial next item via the item width in global.css.
import {
  useCallback,
  useEffect,
  useRef,
  useState,
} from "react";
import type {
  ReactNode,
  KeyboardEvent as ReactKeyboardEvent,
  PointerEvent as ReactPointerEvent,
} from "react";

export interface CarouselItem {
  key: string;
  heading: string;
  subheading?: string;
  content: ReactNode;
}

interface CarouselProps {
  items: CarouselItem[];
  ariaLabel: string;
}

// Critically damped spring: stiffness 180, damping = 2*sqrt(stiffness).
const STIFFNESS = 180;
const DAMPING = 2 * Math.sqrt(STIFFNESS);
// How far the release velocity projects to choose the landing snap.
const MOMENTUM_S = 0.25;

function prefersReducedMotion(): boolean {
  if (typeof window === "undefined" || !window.matchMedia) return false;
  return window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

export function Carousel({ items, ariaLabel }: CarouselProps) {
  const viewRef = useRef<HTMLDivElement | null>(null);
  const trackRef = useRef<HTMLDivElement | null>(null);
  const [index, setIndex] = useState(0); // settled snap index

  const offsetRef = useRef(0); // current px scrolled
  const velRef = useRef(0); // px/ms (offset space)
  const frameRef = useRef(0);
  const draggingRef = useRef(false);
  const startXRef = useRef(0);
  const startOffsetRef = useRef(0);
  const movesRef = useRef<{ x: number; t: number }[]>([]);
  const indexRef = useRef(0);
  indexRef.current = index;

  // Width of one item incl. gap — re-measured on demand so it tracks resize.
  const itemAdvance = useCallback(() => {
    const track = trackRef.current;
    const view = viewRef.current;
    if (!track || !view || !track.firstElementChild) return view ? view.clientWidth * 0.78 : 376;
    const itemW = (track.firstElementChild as HTMLElement).offsetWidth;
    const gap = parseFloat(getComputedStyle(track).gap || "16") || 16;
    return itemW + gap;
  }, []);

  const applyOffset = useCallback(
    (o: number) => {
      const track = trackRef.current;
      const view = viewRef.current;
      if (!track || !view) return;
      const adv = itemAdvance();
      const maxScroll = Math.max(0, track.scrollWidth - view.clientWidth + adv * 0.22);
      offsetRef.current = Math.max(-adv * 0.1, Math.min(o, maxScroll));
      track.style.transform = `translate3d(${-offsetRef.current}px, 0, 0)`;
    },
    [itemAdvance],
  );

  // Spring-settle to a snap index. Interrupts any running spring (so a new
  // gesture or key press reverses direction mid-motion), then eases from the
  // live offset to the target with a critically damped response.
  const settleTo = useCallback(
    (target: number, velocity: number) => {
      cancelAnimationFrame(frameRef.current);
      const adv = itemAdvance();
      const targetOffset = Math.max(0, Math.min(items.length - 1, target)) * adv;
      setIndex(Math.max(0, Math.min(items.length - 1, target)));
      if (prefersReducedMotion()) {
        applyOffset(targetOffset);
        velRef.current = 0;
        return;
      }
      let p = offsetRef.current;
      let v = velocity;
      let last = performance.now();
      const step = (now: number) => {
        const dt = Math.min(32, now - last) / 1000;
        last = now;
        const a = (targetOffset - p) * STIFFNESS - v * DAMPING;
        v += a * dt;
        p += v * dt;
        offsetRef.current = p;
        applyOffset(p);
        if (Math.abs(targetOffset - p) < 0.5 && Math.abs(v) < 0.15) {
          offsetRef.current = targetOffset;
          applyOffset(targetOffset);
          velRef.current = 0;
          return;
        }
        frameRef.current = requestAnimationFrame(step);
      };
      frameRef.current = requestAnimationFrame(step);
    },
    [applyOffset, itemAdvance, items.length],
  );

  const onPointerDown = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      const track = trackRef.current;
      if (!track || e.button !== 0) return;
      cancelAnimationFrame(frameRef.current); // interrupt: gesture wins
      draggingRef.current = true;
      startXRef.current = e.clientX;
      startOffsetRef.current = offsetRef.current;
      movesRef.current = [{ x: e.clientX, t: e.timeStamp }];
      velRef.current = 0;
      track.setPointerCapture(e.pointerId);
      track.style.cursor = "grabbing";
    },
    [],
  );

  const onPointerMove = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      if (!draggingRef.current) return;
      const dx = e.clientX - startXRef.current;
      applyOffset(startOffsetRef.current - dx);
      const moves = movesRef.current;
      moves.push({ x: e.clientX, t: e.timeStamp });
      if (moves.length > 6) moves.shift();
      const first = moves[0];
      const last = moves[moves.length - 1];
      if (first && last && last.t > first.t) {
        velRef.current = -(last.x - first.x) / (last.t - first.t);
      }
    },
    [applyOffset],
  );

  const endDrag = useCallback(
    (e: ReactPointerEvent<HTMLDivElement>) => {
      if (!draggingRef.current) return;
      draggingRef.current = false;
      const track = trackRef.current;
      if (track) {
        track.style.cursor = "";
        if (e.pointerType !== "mouse") track.releasePointerCapture?.(e.pointerId);
      }
      const adv = itemAdvance();
      const projected = offsetRef.current + velRef.current * (MOMENTUM_S * 1000);
      const target = Math.max(0, Math.min(items.length - 1, Math.round(projected / adv)));
      settleTo(target, velRef.current);
    },
    [itemAdvance, settleTo, items.length],
  );

  const onKey = useCallback(
    (e: ReactKeyboardEvent<HTMLDivElement>) => {
      const cur = indexRef.current;
      if (e.key === "ArrowLeft") {
        e.preventDefault();
        settleTo(cur - 1, 0);
      } else if (e.key === "ArrowRight") {
        e.preventDefault();
        settleTo(cur + 1, 0);
      } else if (e.key === "Home") {
        e.preventDefault();
        settleTo(0, 0);
      } else if (e.key === "End") {
        e.preventDefault();
        settleTo(items.length - 1, 0);
      }
    },
    [settleTo, items.length],
  );

  // Re-measure + re-clamp on resize; clean up the rAF on unmount.
  useEffect(() => {
    const onResize = () => {
      const adv = itemAdvance();
      applyOffset(Math.max(0, Math.min(items.length - 1, Math.round(offsetRef.current / adv))) * adv);
    };
    window.addEventListener("resize", onResize);
    return () => {
      window.removeEventListener("resize", onResize);
      cancelAnimationFrame(frameRef.current);
    };
  }, [items.length, itemAdvance, applyOffset]);

  return (
    <div
      className="rs-carousel"
      ref={viewRef}
      style={{ overflow: "hidden" }}
    >
      <div
        className="rs-carousel-track"
        ref={trackRef}
        tabIndex={0}
        role="group"
        aria-roledescription="carousel"
        aria-label={ariaLabel}
        onKeyDown={onKey}
        onPointerDown={onPointerDown}
        onPointerMove={onPointerMove}
        onPointerUp={endDrag}
        onPointerCancel={endDrag}
        style={{ cursor: "grab", overflow: "visible", touchAction: "pan-y", willChange: "transform" }}
      >
        {items.map((it, i) => (
          <article
            key={it.key}
            className="rs-carousel-item"
            aria-label={`${it.heading}${it.subheading ? ` — ${it.subheading}` : ""} (${i + 1} of ${items.length})`}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "baseline", gap: 8 }}>
              <h3 style={{ textTransform: "none", color: "var(--rs-text)", letterSpacing: 0, fontSize: "0.875rem" }}>
                {it.heading}
              </h3>
              <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
                {i + 1}/{items.length}
              </span>
            </div>
            {it.subheading ? (
              <p style={{ margin: 0, fontSize: "0.8125rem", color: "var(--rs-text-2)", lineHeight: 1.5 }}>
                {it.subheading}
              </p>
            ) : null}
            {it.content}
          </article>
        ))}
      </div>

      <div className="rs-carousel-controls">
        <button
          type="button"
          className="rs-btn rs-btn--sm"
          aria-label="Previous profile"
          disabled={index <= 0}
          onClick={() => settleTo(index - 1, 0)}
        >
          ← Previous
        </button>
        <span className="rs-mono" style={{ fontSize: "0.7rem", color: "var(--rs-text-3)" }}>
          {index + 1} of {items.length}
        </span>
        <button
          type="button"
          className="rs-btn rs-btn--sm"
          aria-label="Next profile"
          disabled={index >= items.length - 1}
          onClick={() => settleTo(index + 1, 0)}
        >
          Next →
        </button>
      </div>
    </div>
  );
}
