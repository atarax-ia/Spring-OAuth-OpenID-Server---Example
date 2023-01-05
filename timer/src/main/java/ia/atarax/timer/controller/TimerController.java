// FROM: https://www.infoq.com/news/2022/12/spring-authorization-server-1-0/

package ia.atarax.timer.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

@RestController
public class TimerController {

    @GetMapping("/time")
    public String retrieveTime() {
        DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern("HH:mm:ss");
        LocalTime localTime = LocalTime.now();
        return dateTimeFormatter.format(localTime);
    }
}
