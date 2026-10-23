package demo;

import dev.chimera.runtime.ChimeraRuntime;

public final class Main {
    public static void main(String[] args) {
        try {
            System.loadLibrary("chimera_native");
        } catch (Throwable ignored) {
            // demo runs without the optional JNI library
        }
        // Optional license handshake: the protected jar bakes /chimera/auth.dat; the launcher
        // supplies the account credentials. Without credentials the demo still runs with poison
        // values, which is exactly the intended degraded behaviour.
        String account = System.getProperty("chimera.demo.account");
        if (account != null) {
            String password = System.getProperty("chimera.demo.password", "");
            String hwid = System.getProperty("chimera.demo.hwid", "demo-hwid");
            System.out.println("auth=" + ChimeraRuntime.authenticate(account, password, hwid));
        }
        System.out.println("label=" + License.label());
        System.out.println("check=" + License.check("HWID-ABC"));
        System.out.println("score=" + License.score(2, 3));
        System.out.println("bonus=" + new Bonus().calc(7));
        System.out.println("damage=" + Damage.hit(2, 3));
        System.out.println("ratio=" + Damage.ratio(2, 3));
        System.out.println("vm=" + VmCalc.addMul(2, 3));
        try {
            System.out.println("hwid=" + Hwid.hash("abc"));
        } catch (Throwable t) {
            System.out.println("hwid=unavailable(" + t.getClass().getSimpleName() + ")");
        }
    }
}
