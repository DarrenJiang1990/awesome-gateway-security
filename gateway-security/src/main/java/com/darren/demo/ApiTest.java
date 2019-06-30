package com.darren.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * <p>
 * <b>Class name</b>: ApiTest
 * </p>
 * <p>
 * <b>Class description</b>: Class description goes here.
 * </p>
 * <p>
 * <b>Author</b>: Jiangdr
 * <b>Date </b>:  2019-06-30
 * </p>
 * <b>Change History</b>:<br/>
 * <p>
 * <p>
 * <pre>
 * Date          Author       Revision     Comments
 * ----------    ----------   --------     ------------------
 * 2019-06-30    Jiangdr       1.0          Initial Creation
 *
 * </pre>
 */
@RequestMapping("/api")
@RestController
public class ApiTest {

    @GetMapping("/demo")
    private String  demo(){
        return "demo";
    }
}
