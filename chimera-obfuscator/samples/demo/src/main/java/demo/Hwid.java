package demo;

import dev.chimera.annotations.ChimeraNative;

public final class Hwid {
    private Hwid() {
    }

    @ChimeraNative("hwidHash")
    public static String hash(String input) {
        return "native:" + input;
    }
}
