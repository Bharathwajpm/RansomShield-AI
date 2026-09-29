import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";
import type { DemoState } from "./types";

interface DemoContextValue {
  state: DemoState;
  setState: (s: DemoState) => void;
  /** 0..1 progress of the scripted attack scenario */
  scenarioProgress: number;
  scenarioRunning: boolean;
  runScenario: () => void;
  stopScenario: () => void;
  /** increments every second — used to make "live" panels feel alive */
  tick: number;
}

const DemoContext = createContext<DemoContextValue | null>(null);

export function DemoProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<DemoState>("SAFE");
  const [scenarioProgress, setScenarioProgress] = useState(0);
  const [scenarioRunning, setScenarioRunning] = useState(false);
  const [tick, setTick] = useState(0);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    const i = setInterval(() => setTick((t) => t + 1), 1000);
    return () => clearInterval(i);
  }, []);

  const stopScenario = useCallback(() => {
    if (timer.current) clearInterval(timer.current);
    timer.current = null;
    setScenarioRunning(false);
  }, []);

  const runScenario = useCallback(() => {
    stopScenario();
    setScenarioProgress(0);
    setState("SAFE");
    setScenarioRunning(true);
    let p = 0;
    timer.current = setInterval(() => {
      p += 0.02;
      setScenarioProgress(Math.min(1, p));
      if (p > 0.28 && p < 0.62) setState("WARNING");
      else if (p >= 0.62) setState("CRITICAL");
      if (p >= 1) {
        if (timer.current) clearInterval(timer.current);
        timer.current = null;
        setScenarioRunning(false);
      }
    }, 220);
  }, [stopScenario]);

  useEffect(() => () => stopScenario(), [stopScenario]);

  const value = useMemo(
    () => ({ state, setState, scenarioProgress, scenarioRunning, runScenario, stopScenario, tick }),
    [state, scenarioProgress, scenarioRunning, runScenario, stopScenario, tick],
  );

  return <DemoContext.Provider value={value}>{children}</DemoContext.Provider>;
}

export function useDemo() {
  const ctx = useContext(DemoContext);
  if (!ctx) throw new Error("useDemo must be used inside <DemoProvider>");
  return ctx;
}
