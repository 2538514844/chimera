package fixtures;

/** Pure-logic state object used by the M9 object/field/call tests. */
public final class VmState {

    public int hp;
    public long gold;
    public double factor;

    public static int LIMIT = 20;
    public static double BASE = 2.0;

    public VmState(int hp, long gold, double factor) {
        this.hp = hp;
        this.gold = gold;
        this.factor = factor;
    }

    public static int add(int a, int b) {
        return a + b;
    }

    public static double scale(double value, double factor) {
        return value * factor;
    }

    public static int getLimit() {
        return LIMIT;
    }

    public int getHp() {
        return hp;
    }

    public void setHp(int hp) {
        this.hp = hp;
    }

    public long getGold() {
        return gold;
    }

    public void setGold(long gold) {
        this.gold = gold;
    }

    public double getFactor() {
        return factor;
    }

    public void setFactor(double factor) {
        this.factor = factor;
    }

    public static void setLimit(int limit) {
        LIMIT = limit;
    }
}
