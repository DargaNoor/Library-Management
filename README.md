import java.util.*;

public class Main {
    public static void main(String[] args) {
        // Example JSON string input
        String jsonString = "{\"a\":{\"0\":\"d1\",\"1\":\"d2\",\"2\":\"d3\"},\"b\":{\"0\":\"e1\",\"1\":\"e2\",\"2\":\"e3\"},\"c\":{\"0\":\"f1\",\"1\":\"f2\",\"2\":\"f3\"}}";

        // Call the function to get the parallel elements
        List<List<String>> result = getParallelElements(jsonString);

        // Print the result
        for (List<String> innerList : result) {
            System.out.println(innerList);
        }
    }

    public static List<List<String>> getParallelElements(String jsonString) {
        // Manually parse the JSON string
        Map<String, Map<String, String>> jsonData = manualJsonParse(jsonString);

        // Find the maximum length of the inner JSON objects
        int maxLength = 0;
        for (Map<String, String> innerObject : jsonData.values()) {
            maxLength = Math.max(maxLength, innerObject.size());
        }

        // Initialize the result list
        List<List<String>> result = new ArrayList<>();
        for (int i = 0; i < maxLength; i++) {
            result.add(new ArrayList<>());
        }

        // Populate the result list with parallel elements
        for (Map<String, String> innerObject : jsonData.values()) {
            for (int i = 0; i < maxLength; i++) {
                String value = innerObject.get(String.valueOf(i));
                if (value != null) {
                    result.get(i).add(value);
                }
            }
        }

        return result;
    }

    public static Map<String, Map<String, String>> manualJsonParse(String jsonString) {
        // Simple manual JSON parser for the given format
        jsonString = jsonString.trim().substring(1, jsonString.length() - 1); // Remove outer {}
        String[] parts = jsonString.split("\\},\\\"");
        Map<String, Map<String, String>> result = new HashMap<>();

        for (String part : parts) {
            part = part.replaceAll("\\\"", "").replaceAll("\\{", "").replaceAll("\\}", "");
            String[] keyValuePairs = part.split(",");
            String key = keyValuePairs[0].split("\\:")[0];
            Map<String, String> innerMap = new HashMap<>();

            for (int i = 1; i < keyValuePairs.length; i++) {
                String[] pair = keyValuePairs[i].split("\\:");
                if (pair.length == 2) {
                    innerMap.put(pair[0], pair[1]);
                }
            }

            result.put(key, innerMap);
        }

        return result;
    }
}




















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
