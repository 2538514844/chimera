package dev.chimera.attach;

/**
 * Helper process entry: attaches to the parent JVM and loads this jar as a java agent.
 *
 * <p>Uses reflection on {@code com.sun.tools.attach.VirtualMachine} so the build has no compile-time
 * dependency on the {@code jdk.attach} module. Attaching from a different process is allowed by
 * default (unlike self-attach, which needs {@code -Djdk.attach.allowAttachSelf}).</p>
 */
public final class Attacher {

    private Attacher() {
    }

    public static void main(String[] args) {
        if (args.length < 2) {
            System.err.println("usage: Attacher <pid> <agent.jar>");
            System.exit(2);
        }
        try {
            Class<?> vmClass = Class.forName("com.sun.tools.attach.VirtualMachine");
            Object vm = vmClass.getMethod("attach", String.class).invoke(null, args[0]);
            try {
                vmClass.getMethod("loadAgent", String.class).invoke(vm, args[1]);
            } finally {
                vmClass.getMethod("detach").invoke(vm);
            }
            System.out.println("[chimera-attach] loadAgent OK");
        } catch (Throwable failure) {
            System.err.println("[chimera-attach] attach failed: " + failure);
            failure.printStackTrace();
            System.exit(3);
        }
    }
}
