package dev.chimera.transform.cfg;

/** Executable fixture for the S6 control-flow tests. */
public final class CfgFixture {

    public static int staticState = 5;

    private CfgFixture() {
    }

    public static int branchy(int x) {
        if (x > 3) {
            return x * 2 + 1;
        }
        return x - 7;
    }

    public static int loop(int n) {
        int sum = 0;
        for (int i = 0; i < n; i++) {
            sum += i * 3;
        }
        return sum;
    }

    public static int switchy(int x) {
        switch (x) {
            case 0:
                return 11;
            case 3:
                return 33;
            default:
                return x + 7;
        }
    }

    public static int throwsWhenNegative(int x) {
        if (x < 0) {
            throw new IllegalArgumentException("negative-" + x);
        }
        return x * 5;
    }

    public static int catches(int x) {
        try {
            return 100 / x;
        } catch (RuntimeException e) {
            return -1;
        }
    }

    public static long constantLong(long x) {
        return x + 1234567890123L;
    }

    public static int constants() {
        return 1234567 + 89;
    }

    public static boolean booleany(boolean value) {
        return !value;
    }

    public static String stringy(String value) {
        return value + "!";
    }

    public static int helper(int x) {
        return x * x;
    }

    public static int callsHelper(int x) {
        return helper(x) + 1;
    }

    public static void voidLoop(int n) {
        for (int i = 0; i < n; i++) {
            staticState += i;
        }
    }
}