<?php
class User {
    protected  $userid;
    protected  $usertype;
    protected  $model;
    public  $params;
    public static $menu;
    public static $metatags;
    public static $metaprop;
    use General, Session;

    function __construct($method,$params) {
        $this->params = $params;
        $this->model = new UserModel();
        self::$menu = $method;
        $seopage = preg_replace('/[_]/', '-', $method);
        $tags = $this->model->metatags($seopage);
        self::$metatags = (object)$tags[0];
        self::$metaprop = (object)$tags[1];

    }

    public function isMemberLogin(){
        if(auth::IsLogin('member')){
            return true;
        }else{
            $this->redirect(PUBLIC_URL, "Session Expired~err");
        }
    }


    public function index($param){
        define('SUBTITLE','Innovative Business Solution Provider');
        $response = $this->model->indexPageSrc($param);
        $this->render(__FUNCTION__, $response, "default", "user");
    }

    public function contact_us($param){
        define('SUBTITLE','Contact Technets');
        $response = $this->model->contactPageSrc($param);
        $this->render(__FUNCTION__, $response);
    }

    public function about_us($param){
        define('SUBTITLE','About Technets');
        $this->render(__FUNCTION__, $response);
    }

     public function web_development($param){
        define('SUBTITLE','Web Development');
        $this->render(__FUNCTION__, $response);
    }
    
    
 public function ui_xi_design($param){
        define('SUBTITLE','UI XI Design');
        $this->render(__FUNCTION__, $response);
    }
    
    public function api_intigration($param){
        define('SUBTITLE','UI XI Design');
        $this->render(__FUNCTION__, $response);
    }
    
    
    public function mobile_application($param){
        define('SUBTITLE','Mobile Application');
        $this->render(__FUNCTION__, $response);
    }

    public function e_commerse_services($param){
        define('SUBTITLE','E-commerce Services');
        $this->render(__FUNCTION__, $response);
    }
    
     public function bulk_sms($param){
        define('SUBTITLE','Bulk SMS');
        $this->render(__FUNCTION__, $response);
    }
    
    public function seo_facility($param){
        define('SUBTITLE','SEO');
        $this->render(__FUNCTION__, $response);
    }
    
    public function meet_our_team($param){
        define('SUBTITLE','Technets Team');
        $this->render(__FUNCTION__, $response);
    }

    public function visitors($param){
      $response = $this->model->saveVisitors($_POST);
      if($response){
        echo 'Thank you very much for visiting Technets! We are delighted to have you on board!. We will notify you as soon as we launch it.';
      }else{
        echo 'Thank You! We Will Notify You on This Email.';
      }

    }

    public function send_enquiry($param){
        $response = $this->model->saveEnquiry($param);
        include('mail.controller.php');
        $mail = new mail();
        $mail->saveEnquiry($_POST);
        $this->redirect(PUBLIC_URL."contact-us", "Thank You! We Will Get Back To You Soon.~suc");
    }

    public function careers($param){
        define('SUBTITLE','Career');
        $response = $this->model->readOpennings($param);
        $this->render(__FUNCTION__, $response);
    }

    public function post_resume($param){
        $link = $this->uploadfile("resume",$this->generateRandomString(15). "_" . time(),
                "assets/cv_resume/",
         array("pdf", "doc", "docx"),
         array("application/msword","application/word","application/pdf"), 10, 2048);
         if($link=="N"){
           $this->redirect(PUBLIC_URL."careers", "Upload Valid Files Only ( doc / docx / pdf).~err");
           exit(0);
         }
         include('mail.controller.php');
         $mail = new mail();
         $mail->postResume($_POST);
         $this->redirect(PUBLIC_URL."careers", "We acknowledge receipt of your resume and application and sincerely appreciate your interest in our company Technets.~suc");
    }

    public function our_portfolio($param){
        define('SUBTITLE','Technets Portfolio');
        $response = $this->model->portfolioPageSrc($param);
        $this->render(__FUNCTION__, $response);
    }

    public function send_feedback($param){
        $response = $this->model->savefeedback($param);
        include('mail.controller.php');
        $mail = new mail();
        $mail->savefeedback($_POST);
        $this->redirect(PUBLIC_URL, "Thank You! For Your Valuable Feedback.~suc");
    }


    public function captcha($param) {
       $cap = new captcha($_POST['typ']);
       echo $cap->phpcaptcha("#".$param[0], "#".$param[1], $param[2], $param[3], $param[4], $param[5]);
    }


}
