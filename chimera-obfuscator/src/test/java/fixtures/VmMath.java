package fixtures;

import dev.chimera.annotations.ChimeraVM;

/**
 * M9 fixture: static int/long/double methods that the VM transformer virtualizes, plus a few
 * methods outside the supported subset that must stay ordinary Java bytecode.
 */
public final class VmMath {

    private VmMath() {
    }

    // ---------------------------------------------------------------- straight-line

    @ChimeraVM
    public static int addMul(int a, int b) {
        return (a + b) * 3;
    }

    @ChimeraVM
    public static long longChain(long x, int y) {
        return (x * 2L + (long) y) % 1000L;
    }

    @ChimeraVM
    public static double ratio(int a, int b) {
        return a * 1.5 + b / 2.0;
    }

    @ChimeraVM
    public static int mix(long x, double y) {
        int a = (int) x;
        long b = (long) y;
        return (int) (a * 2L + b);
    }

    @ChimeraVM
    public static int div(int a, int b) {
        return a / b;
    }

    // ---------------------------------------------------------------- branches

    @ChimeraVM
    public static int branchyAnnotated(int x) {
        return x > 0 ? x + 1 : -x;
    }

    @ChimeraVM
    public static int clamp(int value, int low, int high) {
        if (value < low) {
            return low;
        }
        if (value > high) {
            return high;
        }
        return value;
    }

    @ChimeraVM
    public static int max3(int a, int b, int c) {
        int best = a;
        if (b > best) {
            best = b;
        }
        if (c > best) {
            best = c;
        }
        return best;
    }

    @ChimeraVM
    public static int longCmp(long a, long b) {
        if (a < b) {
            return -1;
        } else if (a > b) {
            return 1;
        }
        return 0;
    }

    @ChimeraVM
    public static int doubleCmp(double a, double b) {
        if (a < b) {
            return -1;
        } else if (a > b) {
            return 1;
        }
        return 0;
    }

    @ChimeraVM
    public static int bitMix(int a, int b) {
        return ((a & 0xF0F0) | (b << 4)) ^ (a >>> 8);
    }

    // ---------------------------------------------------------------- loops

    @ChimeraVM
    public static int loops(int n) {
        int sum = 0;
        for (int i = 0; i < n; i++) {
            sum += i;
        }
        return sum;
    }

    @ChimeraVM
    public static int sumTo(int n) {
        int sum = 0;
        int i = 1;
        while (i <= n) {
            sum += i;
            i++;
        }
        return sum;
    }

    @ChimeraVM
    public static int collatz(int n) {
        int steps = 0;
        while (n != 1) {
            if ((n & 1) == 0) {
                n = n / 2;
            } else {
                n = n * 3 + 1;
            }
            steps++;
        }
        return steps;
    }

    // ---------------------------------------------------------------- object fields & calls

    @ChimeraVM
    public static double dist(VmState state) {
        return Math.sqrt((double) (state.hp * state.hp) + (double) (state.gold * state.gold));
    }

    @ChimeraVM
    public static int hpAfterDamage(VmState state, int damage) {
        int hp = state.hp - damage;
        if (hp < 0) {
            hp = 0;
        }
        if (hp > VmState.LIMIT) {
            hp = VmState.LIMIT;
        }
        return hp;
    }

    @ChimeraVM
    public static int addViaBridge(int a, int b) {
        return VmState.add(a, b);
    }

    @ChimeraVM
    public static double scaled(VmState state, double factor) {
        return VmState.scale(state.factor, factor);
    }

    @ChimeraVM
    public static long goldPlus(VmState state, long bonus) {
        return state.gold + bonus;
    }

    /** Direct PUTFIELD + GETFIELD. */
    @ChimeraVM
    public static int writeHp(VmState state, int value) {
        state.hp = value;
        return state.hp;
    }

    /** INVOKEVIRTUAL setter (void) followed by INVOKEVIRTUAL getter. */
    @ChimeraVM
    public static int setHpViaVm(VmState state, int value) {
        state.setHp(value);
        return state.getHp();
    }

    @ChimeraVM
    public static long setGoldViaVm(VmState state, long value) {
        state.setGold(value);
        return state.getGold();
    }

    @ChimeraVM
    public static double factorViaVm(VmState state, double value) {
        state.setFactor(value);
        return state.getFactor();
    }

    /** PUTSTATIC + GETSTATIC. */
    @ChimeraVM
    public static int setLimitViaVm(int value) {
        VmState.LIMIT = value;
        return VmState.LIMIT;
    }

    @ChimeraVM
    public static int hpPlus(VmState state, int delta) {
        return state.getHp() + delta;
    }

    @ChimeraVM
    public static int gcd(int a, int b) {
        while (b != 0) {
            int remainder = a % b;
            a = b;
            b = remainder;
        }
        return a;
    }

    // ---------------------------------------------------------------- unsupported

    /** Unsupported: object return type. */
    @ChimeraVM
    public static String text() {
        return "vm";
    }

    /** Unsupported: instance method (VM requires static). */
    @ChimeraVM
    public int instance(int x) {
        return x + 1;
    }

    /** Plain Java control method, never annotated. */
    public static int plain(int x) {
        return x > 0 ? x : -x;
    }
}
