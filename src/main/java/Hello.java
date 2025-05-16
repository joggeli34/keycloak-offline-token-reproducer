import io.quarkus.runtime.Startup;
import jakarta.enterprise.context.ApplicationScoped;

@ApplicationScoped
public class Hello {
    @Startup
    void startup() {
        System.out.println("Hello, Quarkus!");
    }
}
