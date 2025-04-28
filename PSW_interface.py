if __name__ == '__main__':
    from kivy.app import App
    from kivy.uix.popup import Popup
    from kivy.uix.boxlayout import BoxLayout
    from kivy.uix.label import Label
    from kivy.uix.textinput import TextInput
    from kivy.uix.button import Button
    from kivy.uix.progressbar import ProgressBar
    from kivy.core.window import Window
    from kivy.graphics import Color, Rectangle
    from kivy.utils import platform
    from kivy.clock import Clock
import os
from multiprocessing import Process, Queue, set_start_method
from PSW_file_v2 import CryptoArc

def crypto_worker(mode, input_path, output_path, password, code, progress_queue):
    def progress_wrapper(current, total):
        progress_queue.put((current, total))
    
    crypto = CryptoArc(
        mode,
        input_path,
        output_path,
        password,
        code,
        progress_wrapper
    )
    crypto.run()
    
if __name__ == '__main__':

    class CustomPopup(Popup):
        def __init__(self, text, **kwargs):
            super().__init__(**kwargs)
            self.title = ''
            self.size_hint = (0.6, 0.4)  

            # Create content layout
            content = BoxLayout(orientation='vertical', padding=10, spacing=10)
            
            # Add text label
            content.add_widget(Label(
                text=text,
                halign='center'
            ))
            
            # Add OK button
            ok_button = Button(
                text='OK', 
                size_hint=(1, 0.4),
                background_normal='',
                background_color=(0.25, 0.65, 0.96, 1) 
            )
            ok_button.bind(on_press=self.dismiss) 
            
            content.add_widget(ok_button)
            self.content = content
            
    class CryptoApp(App):
        def build(self):    
            self.title = "File Encrypt/Decrypt"
            main_layout = BoxLayout(orientation='vertical', spacing=10, padding=10)
            
            # Create drop zone
            self.drop_zone = Label(
                text='Drag and Drop File Here',
                size_hint=(1, 0.5),
                color=(0,0,0,1)
            )
            
            with self.drop_zone.canvas.before:
                Color(0.9, 0.9, 0.9, 1)
                self.rect = Rectangle(pos=self.drop_zone.pos, size=self.drop_zone.size)
            
            self.drop_zone.bind(pos=self.update_rect, size=self.update_rect)
            main_layout.add_widget(self.drop_zone)

            # File path input
            self.file_path = TextInput(
                hint_text='File path',
                multiline=False,
                size_hint=(1, None),
                height=50)
            main_layout.add_widget(self.file_path)

            # New file name input
            self.new_name = TextInput(
                hint_text='New file name',
                multiline=False,
                size_hint=(1, None),
                height=50)
            main_layout.add_widget(self.new_name)

            # Password input
            self.password = TextInput(
                hint_text='Password',
                password=True,
                multiline=False,
                size_hint=(1, None),
                height=50)
            main_layout.add_widget(self.password)

            # Code input
            self.code = TextInput(
                hint_text='Code (numbers and commas only)',
                multiline=False,
                size_hint=(1, None),
                height=50,
                input_filter=lambda text,args: ''.join([c for c in text if c in '0123456789,']))
            main_layout.add_widget(self.code)

            # Buttons
            button_layout = BoxLayout(spacing=10, size_hint=(1, None), height=40)
            self.encrypt_btn = Button(text='Encrypt')
            self.decrypt_btn = Button(text='Decrypt')
            button_layout.add_widget(self.encrypt_btn)
            button_layout.add_widget(self.decrypt_btn)
            main_layout.add_widget(button_layout)

            # Progress Bar
            self.progress_bar = ProgressBar(
                size_hint=(1, None),
                height=20,
                max=100
            )
            main_layout.add_widget(self.progress_bar)

            # Bind window events
            Window.bind(on_drop_file=self.handle_drop)
            self.encrypt_btn.bind(on_press=self.encrypt)
            self.decrypt_btn.bind(on_press=self.decrypt)
            Clock.schedule_once(lambda dt: self.update_rect(self.drop_zone, None))
            
            return main_layout

        def update_rect(self, instance, value):
            self.rect.pos = instance.pos
            self.rect.size = instance.size
            
        def handle_drop(self, window, file_path, x, y):
            
            if x>10 and x<10+self.rect.size[0] and y>10 and y<10+self.rect.size[1]:
                file_path = file_path.decode('utf-8')
                self.file_path.text = file_path
                base = os.path.splitext(os.path.basename(file_path))[0]
                ext = os.path.splitext(file_path)[1]
                if not(base.endswith("_encrypted")):
                    self.new_name.text = f"{base}_encrypted"
                else:
                    self.new_name.text = f"{base}"
                    
        def update_progress(self, dt):
            while not self.progress_queue.empty():
                current, total = self.progress_queue.get()
                self.progress_bar.value = int((current / total) * 100)
            if self.progress_bar.value>=100:
                Clock.unschedule(self.update_progress)
                CustomPopup("Operation completed").open()
                self.progress_bar.value = 0
                return 0

            return 1 


        def encrypt(self, instance):
            print("Starting encryption...")
            self.progress_bar.value = 0
            self.progress_queue = Queue()
            
            knncode = self.code.text.split(",") if "," in self.code.text else [self.code.text]
            output_path = os.path.join(
                os.path.dirname(self.file_path.text),
                self.new_name.text
            )
            
            self.crypto_process = Process(
                target=crypto_worker,
                args=(
                    CryptoArc.ENCRYPT,
                    self.file_path.text,
                    output_path,
                    self.password.text,
                    knncode,
                    self.progress_queue
                )
            )
            self.crypto_process.start()
            Clock.unschedule(self.update_progress)
            Clock.schedule_interval(self.update_progress, 0.1)
                

        def decrypt(self, instance):
            print("Starting decryption...")
            self.progress_bar.value = 0
            self.progress_queue = Queue()
            
            
            knncode = self.code.text.split(",") if "," in self.code.text else [self.code.text]
            if len(knncode) > 1:
                knncode.reverse()
            
            self.crypto_process = Process(
                target=crypto_worker,
                args=(
                    CryptoArc.DECRYPT,
                    self.file_path.text,
                    os.path.dirname(self.file_path.text),
                    self.password.text,
                    knncode,
                    self.progress_queue
                )
            )
            self.crypto_process.start()
            Clock.unschedule(self.update_progress)
            Clock.schedule_interval(self.update_progress, 0.1)
            

        def on_stop(self):
            if hasattr(self, 'crypto_process') and self.crypto_process.is_alive():
                self.crypto_process.terminate()
                
if __name__ == '__main__':
    set_start_method("spawn",True)
    CryptoApp().run()