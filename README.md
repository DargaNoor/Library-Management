import java.util.*;

public class JsonTransposePureJava {
    public static void main(String[] args) {
        // Simulating the parsed JSON structure using nested Maps
        Map<String, Map<String, String>> input = new HashMap<>();

        Map<String, String> a = Map.of("x", "d1", "y", "d2", "z", "d3");
        Map<String, String> b = Map.of("x", "e1", "y", "e2", "z", "e3");
        Map<String, String> c = Map.of("x", "f1", "y", "f2", "z", "f3");

        input.put("a", a);
        input.put("b", b);
        input.put("c", c);

        // Get all keys from the first entry (assumes all inner maps have same keys)
        Set<String> innerKeys = input.values().iterator().next().keySet();

        // Prepare the result
        List<List<String>> result = new ArrayList<>();

        for (String innerKey : innerKeys) {
            List<String> row = new ArrayList<>();
            for (String outerKey : input.keySet()) {
                Map<String, String> innerMap = input.get(outerKey);
                row.add(innerMap.get(innerKey));
            }
            result.add(row);
        }

        // Print the result
        for (List<String> row : result) {
            System.out.println(row);
        }
    }
}















import org.json.JSONArray;
import org.json.JSONObject;

import java.util.*;

public class TransposeNamedJson {
    public static void main(String[] args) {
        String jsonString = """
        {
          "a": {"x": "d1", "y": "d2", "z": "d3"},
          "b": {"x": "e1", "y": "e2", "z": "e3"},
          "c": {"x": "f1", "y": "f2", "z": "f3"}
        }
        """;

        JSONObject input = new JSONObject(jsonString);

        // Get all outer keys: a, b, c
        List<String> outerKeys = new ArrayList<>(input.keySet());

        // Collect all unique inner keys: x, y, z
        Set<String> innerKeySet = input.getJSONObject(outerKeys.get(0)).keySet();

        JSONArray result = new JSONArray();

        for (String innerKey : innerKeySet) {
            JSONArray row = new JSONArray();
            for (String outerKey : outerKeys) {
                JSONObject innerObject = input.getJSONObject(outerKey);
                row.put(innerObject.getString(innerKey));
            }
            result.put(row);
        }

        System.out.println(result.toString(2));
    }
}




# Library-Management
Library Management System is a system which maintains the information about the books present in the library, their authors, the members of library to whom books are 
issued and all. This is very difficult to organize manually. Maintenance of all this information manually is a very complex task. Owing to the advancement of technology, 
organization of an Online Library becomes much simple.The maintenance of the records is made efficient, as all the records are stored in the ACCESS database, through 
which data can be retrieved easily. It makes entire process online where student can search books, staff can generate reports and do book transactions.The navigation 
control is provided in all the forms to navigate through the large amount of records. 
The Library Management has been designed to computerize and automate the operations performed over the information about the members, book issues and returns and all 
other operations. This computerization of library helps in many instances of its maintenance. It reduces the workload of management as most of the manual work done is 
reduced.
